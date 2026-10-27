# egnet
egnet => pronounced as "easy net" provides tools and utilities for debugging and troubleshooting network connections, adapters, devices, DNS, and other sysadmin-related tasks.    

These notes first emerged from my habit of writing them down in one place and referencing them later, anytime, anywhere. Later, I became more involved by answering questions frequently and started asking people to refer to these notes.    

Disclosure: The output shown for the utilities mentioned below is compiled for learning purposes. Generally, this information is available in the public domain.  You may not find all the details in your lab/office/dormitory.   

   * [egnet](#egnet)
     * PART-1 
       * [Introductory Concepts](#introductory-concepts)
       * [Campus Network Infrastructure](#Campus-Network-Infrastructure)
       * [Know Network Hardware](#Know-Network-Hardware)
         * [PoE](#poe)   
         * [Network Adapters](#network-adapters)
         * [Storage Controllers and Drives](#storage-controllers-and-drives)
       * [The One with IP](#The-One-with-IP)
         * [`ifconfig`](#ifconfig)
         * [`ip`](#ip)
         * [`ipcalc`](#ipcalc)
         * [`iptraf` IP Traffic Monitor](#iptraf-ip-traffic-monitor)
         * [IP Address and Privacy](#IP-Address-and-Privacy)
       * [Network Management](#Network-Management)
         * [`nmcli`](#nmcli)
         * [`dstat`](#dstat)
       * [Know Wireless Interface](#Know-Wireless-Interface)
         * [`iwconfig`](#iwconfig)
         * [`iwlist`](#iwlist)
         * [`wavemon`](#wavemon)
     * PART-2 
       * [Simple web server](#simple-web-server)
       * [Remote login using `ssh`](#remote-login-using-ssh)
       * [Transfer files using Secure Copy `scp`](#transfer-files-using-secure-copy-scp)
       * [Get files using `wget`](#get-files-using-wget)
       * [HTTP versions](#http-versions)
       * [HTTP Methods](#HTTP-Methods)
       * [The One with Wireshark](#the-one-with-wireshark)
       * [`netstat`](#netstat)
       * [`nmap`](#nmap)
       * [`nc` netcat](#nc-netcat)
       * [Socket Programming](#Socket-Programming)
       * [DNS](#dns)
       * [Email](#email) 
       * [The One with SPF, DKIM and DMARK](#the-one-with-spf-dkim-and-dmark)
       * [The One with LDAP](#the-one-with-ldap)
       * [The One with RADIUS](#the-one-with-radius)
     * PART-3
       * [The One with Security](#the-one-with-security) 
       * [The One with TLS Certificates](#the-one-with-tls-certificates)
       * [The One with Authentication](#the-one-with-authentication)
     * PART-4
       * [QUIC](#quic)   
       * [The One with Disaster Recovery](#the-one-with-disaster-recovery)
       * [The One with VPN](#the-one-with-vpn)
       * [The One with Blocking IP](#the-one-with-blocking-ip)
       * [HPC](#hpc)
       * [The Privacy Conundrum](#The-Privacy-Conundrum)
       * [Movies](#movies)

PART-1    

## Introductory Concepts 

Here are some [Introductory concepts in computer networking](http://intronetworks.cs.luc.edu/current/html/) online. You can skip this section and continue if you are already familiar with this domain or looking for the content below.    

If you are more comfortable reading a paper book like me, see books - [Computer Networking A Top-Down Approach 8th edition by Kurose and Rose](https://gaia.cs.umass.edu/kurose_ross/online_lectures.htm) - they have added SDN, and [Computer Networks: A Systems Approach by Peterson and Davie](https://book.systemsapproach.org/) - they cover Congestion Control in an elegant manner. Another reference book is [Computer & Internet Security: A Hands-on Approach by Wenliang Du](https://amzn.eu/d/hqd1Ncl) from Syracuse University and maintains [Seed Labs](https://seedsecuritylabs.org/) to combine theory and practice.    

If you are a senior undergrad/postgrad student, you should explore [Reproducing Networking Research](https://reproducingnetworkresearch.wordpress.com/) blog and [paper](https://web.stanford.edu/class/cs244/papers/learning-networking-research-by-reproducing.pdf), and [Some course topics with guests](https://web.stanford.edu/class/cs244/). Visit [Barefoot](https://barefootnetworks.com/resources/worlds-fastest-most-programmable-networks/) in the age of programmable networks.    

You do not need to be a Computer Scientist or Computer Engineering graduate to understand and appreciate these topics 😅   

---- 

## Campus Network Infrastructure 

Understand your Campus Network Infrastructure to appreciate how internet and allied services come to your hostel, home, or office.    

Service Provider    
|   
|   
|   
campus (home, office, hostel)    

---- 

## Know Network Hardware    

### PoE    

Power over Ethernet or PoE devices or interface can provide DC power over Ethernet cables - power and network connectivity over a single wire! It's cost-effective. PoE is used for wireless Access Points (APs), IP cameras, VoIP phones, and IoT devices. Please look at them and notice that they are without a separate power adapter.  The network switch should have PoE ports enabled.    

[What is PoE?](https://notes.networklessons.com/poe-what-is-it)    

[Active or Standardized PoE](https://notes.networklessons.com/poe-standards-based)    

[Passive PoE](https://notes.networklessons.com/poe-passive) - used in PoE injectors. The supplied DC current to the device is fixed.   

---- 

###  Network Adapters

It's good to know your network adapters: product, provider, logical names, MAC, capacity in Mbps or Gbps, capabilities, etc.   
Knowledge of adapters and vendors can help with device driver-related issues or updating drivers.   
The network adapter's logical name is visible in the ip command output.   

Sample output-1 with Ethernet (Realtek) and Wireless (Intel)     
```
$ sudo lshw -class network
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

Sample output-2 with WiFi 6.0 and Ethernet interface   
```
$ sudo lshw -class network 
[sudo: authenticate] Password: ********
  *-network:0               
       description: Wireless interface
       product: Wi-Fi 6 AX201                   <== Wi-Fi 6.0 - IEEE 802.11ax, 2x2 Antenna 
       vendor: Intel Corporation
       physical id: 14.3
       bus info: pci@0000:00:14.3
       logical name: wlp0s20f3
       version: 20
       serial: 50:84:92:66:40:36
       width: 64 bits
       clock: 33MHz
       capabilities: pm msi pciexpress msix bus_master cap_list ethernet physical wireless
       configuration: broadcast=yes driver=iwlwifi driverversion=7.0.0-31-generic firmware=77.f39cc7f9.0 QuZ-a0-hr-b0-77.u ip=192.168.1.5 latency=0 link=yes multicast=yes wireless=IEEE 802.11
       resources: iomemory:600-5ff irq:16 memory:6055294000-6055297fff

  *-network:1
       description: Ethernet interface
       product: Ethernet Connection (13) I219-V
       vendor: Intel Corporation
       physical id: 1f.6
       bus info: pci@0000:00:1f.6
       logical name: enp0s31f6
       version: 20
       serial: 38:14:28:58:3a:5a
       capacity: 1Gbit/s
       width: 32 bits
       clock: 33MHz
       capabilities: pm msi bus_master cap_list ethernet physical tp 10bt 10bt-fd 100bt 100bt-fd 1000bt-fd autonegotiation
       configuration: autonegotiation=on broadcast=yes driver=e1000e driverversion=7.0.0-31-generic firmware=0.8-4 latency=0 link=no multicast=yes port=twisted pair
       resources: irq:191 memory:a6100000-a611ffff
```

[Different WiFi Standards and Data Rates](https://www.intel.com/content/www/us/en/support/articles/000005725/wireless/legacy-intel-wireless-products.html)     

lspci can be used to see WiFi or ethernet driver information:    
```
$ lspci | egrep -i --color 'wi-fi|net'
0000:00:14.3 Network controller: Intel Corporation Wi-Fi 6 AX201 (rev 20)
0000:00:1f.6 Ethernet controller: Intel Corporation Ethernet Connection (13) I219-V (rev 20)

$ lspci -vv -s 0000:00:14.3
0000:00:14.3 Network controller: Intel Corporation Wi-Fi 6 AX201 (rev 20)
	Subsystem: Intel Corporation Device 4070
	Control: I/O- Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0
	Interrupt: pin A routed to IRQ 16
	IOMMU group: 9
	Region 0: Memory at 6055294000 (64-bit, non-prefetchable) [size=16K]
	Capabilities: <access denied>
	Kernel driver in use: iwlwifi
	Kernel modules: iwlwifi

$ lspci -vv -s 0000:00:1f.6
0000:00:1f.6 Ethernet controller: Intel Corporation Ethernet Connection (13) I219-V (rev 20)
	Subsystem: Dell Device 0a20
	Control: I/O- Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0
	Interrupt: pin A routed to IRQ 191
	IOMMU group: 15
	Region 0: Memory at a6100000 (32-bit, non-prefetchable) [size=128K]
	Capabilities: <access denied>
	Kernel driver in use: e1000e
	Kernel modules: e1000e
```

For other hardware, using lspci, see the bus info, kernel driver and kernel module:    
```
lspci -k | more 
```

---- 

### Storage Controllers and Drives    

To list drives and storage controllers, use lshw with class disk and storage. The sample output below shows RAID, SATA, NVMe controllers, and NVMe SSD disk.    

```
$ lshw -class disk -class storage
  *-raid                    
       description: RAID bus controller
       product: Volume Management Device NVMe RAID Controller
       vendor: Intel Corporation
       physical id: e
       bus info: pci@0000:00:0e.0
       version: 00
       width: 64 bits
       clock: 33MHz
       capabilities: raid msix pciexpress pm bus_master cap_list
       configuration: driver=vmd latency=0
       resources: iomemory:600-5ff iomemory:600-5ff irq:0 memory:6052000000-6053ffffff memory:a4000000-a5ffffff memory:6055100000-60551fffff
  *-sata
       description: SATA controller
       product: Intel Corporation
       vendor: Intel Corporation
       physical id: 17
       version: 20
       width: 32 bits
       clock: 66MHz
       capabilities: sata msi pm ahci_1.0 bus_master cap_list
       configuration: driver=ahci latency=0
       resources: irq:168 memory:a4100000-a4101fff memory:a4102800-a41028ff memory:a4102000-a41027ff
  *-nvme
       description: Non-Volatile memory controller
       product: Gold P31 SSD
       vendor: SK hynix                                    <== Vendor of NVMe controller 
       physical id: 0
       version: 00
       width: 64 bits
       clock: 33MHz
       capabilities: nvme pm msi msix pciexpress nvm_express bus_master cap_list          <== note NVMe, PCI express
       configuration: driver=nvme latency=0
       resources: irq:-2147483648 memory:a4000000-a4003fff memory:a4004000-a4004fff memory:a4005000-a4005fff
  *-nvme0
       description: NVMe device
       product: BC711 NVMe SK hynix 512GB                   <== Disk Model 
       physical id: 3
       logical name: /dev/nvme0
       version: 41002131
       serial: FNB3N446110803ABC                            <== Disk serial number
       configuration: nqn=nqn.2022-03.com.skhynix:nvme:nvm-subsystem-sn-FNB3N446110803ABC state=live  <== similar to iqn for iSCSI 
     *-namespace:0
          description: NVMe disk
          physical id: 0
          logical name: hwmon2
     *-namespace:1
          description: NVMe disk
          physical id: 2
          logical name: /dev/ng0n1
     *-namespace:2
          description: NVMe disk
          physical id: 1
          bus info: nvme@0:1
          logical name: /dev/nvme0n1                           <== Disk logical name, partitions suffixed as p1, p2, p3, ...
          size: 476GiB (512GB)                                 <== Disk capacity 
          capabilities: gpt-1.00 partitioned partitioned:gpt
          configuration: guid=90ac9bea-be65-4c42-8c6d-4ce4c1234567 logicalsectorsize=512
                         sectorsize=512 wwid=nvme. <truncated_due_to_cold>
```

[NVMe and SATA - a brief comparison](https://www.kingston.com/en/blog/pc-performance/nvme-vs-sata)     

[2 types of M.2 SSDs - SATA SSD and NVMe SSD](https://www.kingston.com/en/blog/pc-performance/two-types-m2-vs-ssd)     

----

## The One with IP   

### `ifconfig`   

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

### `ip`   

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

**WHOIS lookup**  At times, it may be interesting to look up whose ip address it is - while analyzing server logs or email yml files for a possible spammer, etc. You can use [WHOIS Look up](https://www.whatismyip.com/ip-whois-lookup/) or [Arin](https://www.arin.net/). [IPv4 blocks cleared](https://www.arin.net/resources/guide/ipv4/blocks_cleared/) can be seen on Arin.      

---- 

### `ipcalc`   

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

### `iptraf` IP Traffic Monitor   

```
$ sudo iptraf

iptraf-ng 1.2.1

                                    ┌─────────────────────────────────┐
                                    │ IP traffic monitor              │
                                    │ General interface statistics    │
                                    │ Detailed interface statistics   │
                                    │ Statistical breakdowns...       │
                                    │ LAN station monitor             │
                                    │─────────────────────────────────│
                                    │ Filters...                      │
                                    │─────────────────────────────────│
                                    │ Configure...                    │
                                    │─────────────────────────────────│
                                    │ About...                        │
                                    │─────────────────────────────────│
                                    │ Exit                            │
                                    └─────────────────────────────────┘

 Displays current IP traffic information
 Up/Down-Move selector  Enter-execute
```
----

### IP Address and Privacy   

[Is leaking or revealing IP a real problem?](https://www.youtube.com/watch?v=MS7WRuzNYDc)    

What exactly does a VPN do?    

What does a Tor (The Onion Router) do?    

----

## Network Management 

### `nmcli` 

We can use nmcli command to get the status of all network connections - wired, wireless, and any other logical interfaces:   

```
$ nmcli device show
GENERAL.DEVICE:                         enp0s31f6
GENERAL.TYPE:                           ethernet
GENERAL.HWADDR:                         38:14:28:58:3A:5A
GENERAL.MTU:                            1500
GENERAL.STATE:                          100 (connected)
GENERAL.CONNECTION:                     Wired connection 1
GENERAL.CON-PATH:                       /org/freedesktop/NetworkManager/ActiveC>
WIRED-PROPERTIES.CARRIER:               on
IP4.ADDRESS[1]:                         10.10.163.232/24
IP4.GATEWAY:                            10.10.163.1
IP4.ROUTE[1]:                           dst = 10.10.163.0/24, nh = 0.0.0.0, mt >
IP4.ROUTE[2]:                           dst = 0.0.0.0/0, nh = 10.10.163.1, mt =>
IP4.DNS[1]:                             14.139.53.132
IP4.DNS[2]:                             14.139.53.133
IP4.DOMAIN[1]:                          riit.ac.in
IP4.SEARCHES[1]:                        riit.ac.in
IP6.ADDRESS[1]:                         fe80::c895:8320:5054:d3b8/64
IP6.GATEWAY:                            --
IP6.ROUTE[1]:                           dst = fe80::/64, nh = ::, mt = 1024

GENERAL.DEVICE:                         wlp0s20f3
GENERAL.TYPE:                           wifi
GENERAL.HWADDR:                         50:84:92:66:40:36
```

```
$ nmcli 
enp0s31f6: connected to Wired connection 1
        "Intel I219-V"
        ethernet (e1000e), 38:14:28:58:3A:5A, hw, mtu 1500
        ip4 default
        inet4 10.10.163.232/24
        route4 10.10.163.0/24 metric 100
        route4 default via 10.10.163.1 metric 100
        inet6 fe80::c895:8320:5054:d3b8/64
        route6 fe80::/64 metric 1024

wlp0s20f3: connected to IIT_JAMMU
        "Intel 6 AX201"
        wifi (iwlwifi), 50:84:92:66:40:36, hw, mtu 1500
        inet4 172.18.4.99/20
        route4 172.18.0.0/20 metric 600
        route4 169.254.0.0/16 metric 1000
        route4 default via 172.18.0.1 metric 600
        inet6 fe80::437c:dd6a:b7f2:7850/64
        route6 fe80::/64 metric 1024

p2p-dev-wlp0s20f3: disconnected
        "p2p-dev-wlp0s20f3"
        wifi-p2p, hw
```

```
$ nmcli dev wifi
IN-USE  BSSID              SSID                          MODE   CHAN  RATE        SIGNAL  BARS  SECURITY    
        88:B1:E1:28:B8:90  IIT_JMU                       Infra  44    540 Mbit/s  72      ▂▄▆_  WPA2 802.1X 
        88:B1:E1:28:B8:91  IITJMU_Guest                  Infra  44    540 Mbit/s  72      ▂▄▆_  --          
        88:B1:E1:28:B8:92  IIT_JMU                       Infra  1     260 Mbit/s  70      ▂▄▆_  WPA2 802.1X 
        88:B1:E1:28:B8:93  IIT_JAMMU                     Infra  1     260 Mbit/s  69      ▂▄▆_  WPA2 802.1X 
        88:B1:E1:28:B8:94  IITJMU_Guest                  Infra  1     260 Mbit/s  67      ▂▄▆_  --          
        88:B1:E1:28:77:95  IIT_JAMMU                     Infra  11    260 Mbit/s  62      ▂▄▆_  WPA2 802.1X 
```

```
$ nmcli connection show 
NAME                          UUID                                  TYPE      DEVICE    
IITX                          c111ce11-1ee1-1111-b11c-01111c11e1f1  wifi      wlp0s20f3 
lo                            8223145f-2e59-4071-a819-69591583cbc7  loopback  lo        
DIRECT-KUDESKTOP-KJ8OU2HmsTW  3e0c4018-019e-4571-afbc-eae635d030ec  wifi      --        
IITH-Guest-PWD-IITH@2020      a925d747-7042-4453-b9a5-1e91af399b38  wifi      --        
Wired connection 1            90c3df94-7333-30d5-a3e4-020734106b9c  ethernet  --    
```

---- 

### `dstat`   

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

### Monitor Network    

In Linux, [some CLI tools to monitor network traffic](https://www.binarytides.com/linux-commands-monitor-network/).    

----

## Know Wireless Interface   

### `iwconfig`   

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

Starting with Ubuntu 26.04, iwconfig is no longer installed or available for installation. Use iw instead.    

```
apt show iw    
iw list    
iw dev        <== list wireless interfaces    
iw dev <wlp0s20f3> link    <== show link details of wireless device   
sudo iw dev <wlp0s20f3> scan 
```

Use wavemon (monitoring) and nmcli (network management) for more details.     

----

### `iwlist`    

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

### `wavemon` 

Wavemon is NCurses-based Wireless network monitor and shows output updated in realtime.    

[screengrab of wavemon in action](https://github.com/rks101/egnet/blob/main/images/wavemon_home.png)

----


PART-2    

## Simple web server

Python provides a one-line HTTP web server and this is one simple way to show files from a directory or local share.   

Note: a) the directory you execute the command from and its sub directories and files are visible, and b) there is no authentication to access this page. Only IP address and web server port are needed.    

```
$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
127.0.0.1 - - [03/Feb/2021 23:33:21] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [03/Feb/2021 23:33:31] "GET /myvideos/ HTTP/1.1" 200 -
127.0.0.1 - - [03/Feb/2021 23:33:36] "GET /Downloads/ HTTP/1.1" 200 -
^C 
Keyboard interrupt received, exiting.
```

The web server started above can be opened in a web browser: http://0.0.0.0:8000/ (on the same system) or ip_address:8000 on other systems as well. This page can be opened before you close the server using Ctrl+C.   

Note: In case you are struggling to connect to this web server to access files from another system, check your wired/wireless network or the VLAN you are on. It is likely that in a segmented network, users may not access the resources shared by this http web server.   

----

## Remote login using ssh    

One can log in to a Linux system using   
- local login on a desktop/laptop/server using a username and password. Most convenient :) 
- local login using a bootable USB drive for install/repair.
- remote login using a GUI on VM/server using a username and password. This is slow and rare. 
- remote login using a console/terminal on VM/server. Most preferred. 

To log in to a server or virtual machine remotely from your own Linux system, you can use ssh:    
```
ssh remote_username@remote_server_ip_or_name
```

SSH using a pem file:    
```
ssh -i filename.pem remote_username@remote_server_ip_or_name   
```

SSH ignores a private key file (.pem file) if it is accessible to others. You may need to change the permissions of the pem file (600 or 400) to remove access for other users and to remove the error: "Permissions 0664 for 'filename.pem' are too open."    
```
chmod 400 filename.pem  
```

The default port number to use SSH is 22; this port number can be changed at server side in /etc/ssh/sshd_config for Port config.   

----

## Transfer files using Secure Copy scp   

Using Secure Copy or SCP, we can transfer files to and from local to remote systems. Underneath, scp uses SSH for authentication and encryption.    

```
scp SOURCE DESTINATION    

scp  path-of-local-file-or-dir  user@remote-system:/path-to-remote-file-or-dir    

scp  user@remote-system:/path-of-remote-file-dir  path-of-local-file-or-dir

scp -i filename.pem path-of-local-file-or-dir  user@remote-system:/path-to-remote-file-or-dir

scp -i filename.pem user@remote-system:/path-of-remote-file-dir  path-of-local-file-or-dir
```

While writing to the target location, make sure there is no file with the same name. It may get overwritten.   

----

## Get files using wget 

You can download files or documentation with many files using **wget**. This is very much like your own web-doc-ripper!   

```
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://developer.android.com/reference/packages  
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://permission.site    
```

----

## HTTP versions   

HTTP is an application layer protocol that runs the internet (The World Wide Web). Hypertext docs include hyperlinks to other resources on the web pages/apps that can be accessed by clicking often using a mouse/trackpad or, these days, touch/tap on mobile devices - very much like while you are clicking links on this page online.   

HTTP Versions over the years:    

**HTTP/0.9**: First attempt (in 1991) to transfer generic resources using GET method only and resource path: e.g. GET /index.html    

**HTTP/1.0**: In 1996, added [status codes](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes) (200=Success, 301=Resource Moved, 404=Resource not found, 500=Internal server error), PUT and HEAD methods, HTTP headers (Content-* , Accept-*)     

**HTTP/1.1**: In 1997, added a Persistent Connection to allow multiple request/response pairs execution on the same connection without opening new connections each time, added PUT, DELETE methods, added Host header (useful for proxies)     

**HTTP/2**: In 2015, allowed the asynchronous execution of request and response pairs over a single connection (multiplexing), added auto GZip compression, switched from a text-based protocol to a binary protocol, uses HTTP over TLS (HTTPS) always    

**HTTP/3**: In IETF Draft status. Built on QUIC (Quick UDP Internet Connections) instead of TCP to allow quick handshake and to handle latency issues for slow connections. No more HTTP or HTTPS and redirects; every connection is encrypted.     

Reference: [HTTP/0.9 from scratch](https://kmcd.dev/posts/http0.9-from-scratch/) | [HTTP versions](https://www.baeldung.com/cs/http-versions)   

----

## HTTP Methods  

HTTP Get 


HTTP Post


---- 

## The One with Wireshark 

It is fun to see packets down to the protocol level using Wireshark, a real-time network traffic analyzer, or through a saved pcapng file containing packet capture.   

[Download wireshark](https://www.wireshark.org/download.html) | [Docs](https://www.wireshark.org/docs/)   

Start Wireshark with root privileges, open a web browser, and visit a website. Now, please take a look at the packets in Wireshark.   

```
sudo wireshark -i wlp0s20f3 -k          <== wlp0s20f3 is the WiFi interface to monitor, it can be Ethernet or the lo interface. 
[sudo] password for rps: 
 ** (wireshark:189164) 09:41:30.109036 [GUI WARNING] -- QStandardPaths: XDG_RUNTIME_DIR not set, defaulting to '/tmp/runtime-root'
 ** (wireshark:189164) 09:41:30.885545 [Capture MESSAGE] -- Capture Start ...
 ** (wireshark:189164) 09:41:30.966181 [Capture MESSAGE] -- Capture started
 ** (wireshark:189164) 09:41:30.966232 [Capture MESSAGE] -- File: "/tmp/wireshark_wlp0s20f38V89C3.pcapng"
...............................
```
From the Wireshark GUI, you can stop live capture.    
```
 ** (wireshark:189164) 09:41:47.323455 [Capture MESSAGE] -- Capture Stop ...
 ** (wireshark:189164) 09:41:47.343440 [Capture MESSAGE] -- Capture stopped.
 ** (wireshark:189164) 09:41:47.343508 [Capture WARNING] ./ui/capture.c:722 -- capture_input_closed(): 
```

You can filter using a protocol, analyze packets - byte stream or different headers, and payload with them.   

You can build a meaningful context out of a sequence of packets for protocols HTTP / TCP / UDP / IP / Ethernet, etc.   

e.g., A nice visual lesson of [TCP window size scaling](https://networklessons.com/cisco/ccie-routing-switching-written/tcp-window-size-scaling)    

[Sample packet captures to visualize and understand protocol-level details using **cloudshark**](https://www.cloudshark.org/collections/WTRpgLI-GQSDfgzkQixICg)    

**TCPDUMP** - You can also rely on powerful [tcpdump](https://opensource.com/article/18/10/introduction-tcpdump). [tcpdump-cheat-sheet](https://www.comparitech.com/net-admin/tcpdump-cheat-sheet/)    

```
sudo tcpdump port 443 -w https_capture.pcap     <== monitor port 443 for HTTPS traffic over TCP
tcpdump: listening on wlp0s20f3, link-type EN10MB (Ethernet), snapshot length 262144 bytes
^C1308 packets captured                         <== ctrl+c to stop packet capture 
1308 packets received by filter
0 packets dropped by kernel
```
A packet capture file from tcpdump can be analyzed using Wireshark.    

---- 

## nmap    

Network Mapper `nmap` can be used to study networks and ports (services) that are open, closed, filtered, or functional.    

```
$ nmap -p 1-1024 eg.riit.ac.in  
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-13 20:27 IST
Nmap scan report for eg.riit.ac.in (13.126.157.211)
Host is up (0.050s latency).
rDNS record for 13.126.157.211: ec2-13-126-157-211.ap-south-1.compute.amazonaws.com
Not shown: 1022 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 8.66 seconds
```

```
$ nmap -A -T4 eg.riit.ac.in  
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-13 20:36 IST
Nmap scan report for eg.riit.ac.in (13.126.157.211)
Host is up (0.052s latency).
rDNS record for 13.126.157.211: ec2-13-126-157-211.ap-south-1.compute.amazonaws.com
Not shown: 998 filtered ports
PORT    STATE SERVICE VERSION
80/tcp  open  http    Apache httpd
|_http-server-header: Apache
443/tcp open  ssl/ssl Apache httpd (SSL-only mode)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache
|_http-title: E-Governance
| ssl-cert: Subject: commonName=eg.riit.ac.in
| Subject Alternative Name: DNS:eg.riit.ac.in, DNS:www.eg.riit.ac.in
| Not valid before: 2023-10-03T05:31:25
|_Not valid after:  2024-10-27T10:53:42

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.23 seconds
```

```
$ nmap -A -T4 scanme.nmap.org
Starting Nmap 7.80 ( https://nmap.org ) at 2024-03-13 20:30 IST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.30s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 992 closed ports
PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
|   2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
|   256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
|_  256 33:fa:91:0f:e0:e1:7b:1f:6d:05:a2:b0:f1:54:41:56 (ED25519)
25/tcp    filtered smtp
80/tcp    open     http       Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
4444/tcp  filtered krb524
5000/tcp  filtered upnp
5555/tcp  filtered freeciv
9929/tcp  open     nping-echo Nping echo
31337/tcp open     tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.07 seconds
```

man nmap - shows types of nmap scans, options, and examples.   

Using nmap, find the nearest DHCP server with the help of the broadcast-dhcp-discover script.   
```
$ sudo nmap --script broadcast-dhcp-discover -e wlp0s20f3
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-15 16:20 IST
Pre-scan script results:
| broadcast-dhcp-discover: 
|   Response 1 of 1: 
|     Interface: wlp0s20f3
|     IP Offered: 172.18.10.145
|     DHCP Message Type: DHCPOFFER
|     Server Identifier: 172.18.0.1
|     IP Address Lease Time: 5h00m00s
|     Subnet Mask: 255.255.240.0
|     Router: 172.18.0.1
|_    Domain Name Server: 14.139.53.132, 8.8.8.8
WARNING: No targets were specified, so 0 hosts scanned.
Nmap done: 0 IP addresses (0 hosts up) scanned in 10.16 seconds
```

----

## nc netcat 

`nc` or netcat can be used to open arbitrary TCP and UDP connections and listeners. At times, while deploying exploits, nc can be a lifesaver for opening reverse shells and gaining root access on misconfigured systems.    

Here is a simple netcat-based (nat-khat) client and server from the old `man` himself:    

On the server side (a named FIFO pipe opens bash interactively to listen on a port):    
```
             $ rm -f /tmp/f; mkfifo /tmp/f
             $ cat /tmp/f | /bin/sh -i 2>&1 | nc -l 127.0.0.1 1234 > /tmp/f
```
On the client side (connect to the port announced or known):    
```
             $ nc localhost 1234
             $ (shell prompt from localhost)
```

TODO: add examples demonstrated in the class and links to TryHackMe rooms for reverse shells.     

----

## Socket Programming    



---- 

## DNS    

[DNS](https://github.com/rks101/dns)  

---- 

## Email  

* Gmail: [dots in username](https://gmail.googleblog.com/2008/03/2-hidden-ways-to-get-more-from-your.html) do not matter for @gmail.com domain. Where else do you see this in action? IRCTC emails!  
* Gmail: [plus something in username](https://gmail.googleblog.com/2008/03/2-hidden-ways-to-get-more-from-your.html) can be cool for @gmail.com domain.  
* Auto-forward email: [username+caf@domain](https://support.google.com/mail/thread/25788054/auto-forward-mails-are-sent-with-username-caf-domain-instead-of-username-domain)   
* [Send emails from a different address or alias](https://support.google.com/mail/answer/22370)   
* [Add a brand logo to outgoing email with BIMI](https://support.google.com/a/answer/10911320), you need a [VMC](https://support.google.com/a/answer/10911320) with trademarked logo.     

* [10,000 email accounts limit in GSuite/Workplace](https://owasp.org/blog/2023/03/23/gsuite-account-cleanup.html). After a while, someone has to invest in it.    

* [Google Workplace pricing plans](https://workspace.google.com/intl/en_in/pricing.html). Things get costly with per-user per-month plans :(   

* [Gmail sending limits in Google Workspace](https://support.google.com/a/answer/166852)   

* [Enable MTA-STS and TLS reporting](https://support.google.com/a/answer/9276512) to improve email security and reporting.   

* [SMTP](https://www.afternerd.com/blog/smtp/) - Email Transporter   

* [How to Sync Google Calendars with another person](https://www.clrn.org/how-to-sync-google-calendars-with-another-person/) - take care of settings, and you define edit permissions on calendars shared.    

* Have you ever wondered about having a CLI for Google Workplace to manage accounts? Here is a simple guide for [Getting started with Google Apps Manager (GAM)](https://www.tricent.com/blog/getting-started-with-gam)

* Google Apps Manager [GAM](https://github.com/GAM-team/GAM), [GAM Wiki](https://github.com/GAM-team/GAM/wiki/), and [GAM cheatsheet](https://gamcheatsheet.com/GAM%20Cheat%20Sheet%20A4.pdf)   
* Email Client protocols and ports: [SMTP / IMAP / POP3](https://help.dreamhost.com/hc/en-us/articles/215612887-Email-client-protocols-and-port-numbers) - use secure versions.    

* **Understand how emails can be or are being harvested**: <From-field> For quite some time, spammers have been sending unsolicited communication and targeting more general audiences using increasingly aggressive techniques to harvest e-mail addresses from the web, public digital-domains, institute webpages of faculty, staff, and administrative mailboxes, etc. E-mail addresses may also be harvested by e-mail viruses from browser caches and mail spools, and then diffused further in falsified "From:" lines. <app-profile> One more variant has been seen for such spam through impersonating WhatsApp profile or other mobile apps having access to your contacts, calendars and email apps. I liked and have paraphrased [arXiv email protection](https://info.arxiv.org/help/email-protection.html) text as backlinking.      

**Lesson: Data-minimization - Avoid listing and sharing personal or official emails in bulk anywhere. Make it harder for spammers to harvest emails. Good-enough measures work! Showing email without a domain suffix, using [ ], at, dot, images, etc., is better than researching each possibility and not doing it.**
**Privacy policies**: There is a need to address privacy aspects related to data collection. Check the structure of [HyperVerge's privacy policy](https://hyperverge.co/partner-privacy-policy/).     

* **[Don’t click on anything in an unsolicited email or text message.](https://www.forbes.com/sites/daveywinder/2025/02/09/most-sophisticated-gmail-attacks-ever-fbi-says-do-not-click-anything/)**     
As AI-assisted phishing campaigns evolve, it is essential that this dearly beloved tool of user messaging for decades is introduced with caution: pause and think before clicking a link, especially in unsolicited emails, chat messages, and SMS.    

* **[Captcha scams - be careful when giving permissions or running commands](https://indianexpress.com/article/technology/tech-news-technology/fake-captcha-scams-how-im-not-a-robot-could-infect-your-device-10190466/)** 


---- 

## The One with SPF DKIM and DMARK 

While you may have seen email Spam, you should be familiar with SPF, DKIM, and DMARK records. And more recently, BIMI and VMC.    

A comic take on [SPF and DKIM](https://wizardzines.com/comics/spf-dkim/) by Julia/bork   

1. Sender Policy Framework - [SPF](https://www.dmarcanalyzer.com/spf/)   
Sender Policy Framework (SPF) is used to authenticate the sender of an email. With an SPF record in place, Internet Service Providers can verify that a mail server is authorized to send email for a specific domain. An SPF record is a DNS TXT record containing a list of the IP addresses that are allowed to send email on behalf of your domain.
SPF can verify the result as Pass, Neutral, None (Accept), SoftFail, PermError (Flag suspicious), or Fail, TempError (Reject).  
*SPF can fail for forwarded or redirected emails.*   

2. Domain Keys Identified Mail - [DKIM](https://support.google.com/a/answer/180504?hl=en&ref_topic=7564555) and check [DKIM](https://www.dmarcanalyzer.com/dkim/) records    
DKIM stands for DomainKeys Identified Mail and is used for the authentication of an email that’s being sent. Like SPF, DKIM is an open standard for email authentication that is used for DMARC alignment. A DKIM record exists in the DNS, but it is more complex than SPF. DKIM's advantage is that it can survive forwarding, making it superior to SPF and providing a foundation for securing your email.    
*DKIM can fail for anti-spam or content-filtering software that updates the subject in the header or parts of the email messages with a disclaimer. DKIM can fail for [replay attack](https://wordtothewise.com/2014/05/dkim-replay-attacks/) or [by chance](https://noxxi.de/research/breaking-dkim-on-purpose-and-by-chance.html).*    

4. Domain-based Message Authentication, Reporting, and Conformance - [DMARC](https://support.google.com/a/answer/2466563?hl=en) and check [DMARK](https://www.dmarcanalyzer.com/dmarc/) records    
DMARC, an open source standard, uses a concept called alignment to tie the result of two other open source standards,  SPF (a published list of servers that are authorized to send email on behalf of a domain) and DKIM (a tamper-evident domain seal associated with a piece of email), to the content of an email. DMARC ensures the sender's domain matches the domains verified by SPF and DKIM. If the alignment fails, DMARC instructs the recipient server on how to handle the email based on a policy specified in the record.     
*SPF or DKIM alone or both together are not sufficient to control spam. DMARC or ARC, combined with SPF and DKIM, is a good team to fight against spam.*    

Sample yml files with "Show Original" option from mail client - adding soon    

4. Secure/Multipurpose Internet Mail Extensions (S/MIME) is a standard protocol for sending digitally signed and encrypted messages.    

5. [ARC Email authentication](https://support.google.com/a/answer/13198639)   

[What email headers can be spoofed?](https://www.quora.com/Is-it-possible-to-fake-every-line-in-an-email-header-I-know-it-is-possible-to-fake-some-lines-but-what-about-the-signed-by-and-mailed-by-lines-How-secure-is-SPF-and-DKIM-authentication)     

[Signed-by and Mailed-by in email header](https://www.online-tech-tips.com/computer-tips/worry-verification-emails-google/)    
A visible 'Mailed-By' field in the email header indicates that the email was SPF-authenticated. A visible 'Signed-By' field in the email header indicates that the email was DKIM-signed.    

**The one with automated DNS records and Mailed-By headers**: In a SendGrid Mailed-By address, often seen in the return-path header, "**em**" is a subdomain prefix generated by SendGrid's Automated Security domain authentication process. It stands for Email Marketing or **Email Management** and identifies the specific subdomain responsible for handling your domain's SPF (Sender Policy Framework) and DKIM (DomainKeys Identified Mail) records. If you see "em" in your email headers, it means your domain is configured with automated DNS records via SendGrid. e.g. em5296.timeasiasubs.com, em4864.iitjammu.ac.in, em4741.plumsoft.com, etc. Also, an administrator may configure an alias or a TXT record in the DNS zone file. e.g. alias aeg.iitjammu.ac.in set for em4864.iitjammu.ac.in (obtained from SendGrid).     

[Authentication Methods](https://support.google.com/a/answer/10583557)   

**Lesson: You need SPF, DKIM, and DMARC record entries in your DNS. Learn how to add them; it's a simple one-time job. This is also applicable for bulk email sending services and newsletter services. e.g., Sendgrid mailer on-behalf bulk emails, Chipmunk on-behalf bulk emails. The onus is on DNS and Email administrators to ensure that intended readers can find and read emails in the Inbox; otherwise, it can impact intended communication or organizational branding.**    

6. BIMI and VMC - additional reputation    
You can [add a brand logo to outgoing email with BIMI](https://support.google.com/a/answer/10911320), and for this, you need a [VMC](https://support.google.com/a/answer/10911320) with a trademarked logo.
[Verified Emails from signed-by domain](https://support.google.com/mail/answer/13130196)     

7. [Enable Mail Transfer Agent (MTA) Strict Transport Security (STS) and TLS reporting](https://support.google.com/a/answer/9276512) to improve email security and reporting.    


**Spam / Phishing / Whaling / Smishing / Vishing / Quishing **:   

Malicious emails can be categorized as:    

**Spam** - unsolicited junk emails sent in bulk to many harvested email recipients.    
**Phishing** - emails sent to targets purporting to originate from a trusted entity (spoofed emails) to lure individuals into clicking links, downloading attachments, or providing sensitive information, like bank account or transaction details. [Phishing](https://attack.mitre.org/techniques/T1566/) and [Phishing for Information](https://attack.mitre.org/techniques/T1598/) are different.     
**Spear phishing** - emails targeting specific individuals or organizations seeking sensitive information, not random email recipients.    
**Whaling** - emails targeting CXOs or high-position individuals (CEO, CFO, CTO - Fish to Whale) to seek sensitive information.    
**Smishing** - phishing using text on mobile devices by targeting users with specially crafted text messages (SMS, chat).    
**Vishing** - similar to smishing; instead of sending text, the attack vector is a voice call.    
**quishing** - using QR codes for phishing    

Q. An email in Spam, passes all three SPF, DKIM, DMARK. Can it be still a Spam?     
A. Absolutely possible. See the example Spam_all3passed.eml   


There are two anti-phishing mnemonics written as S.T.O.P. Ask the following questions before acting on an email:   

- **S**uspicious in any way?
- **T**elling me to click something? press button? View or download the attachment? 
- **O**ffering me an amazing deal? may be too good to believe? 
- **P**ushing me to do something now? showing urgency? Tricking into missing out on an offer or loss? 
[Reference: AllThingsSecured.com](https://www.allthingssecured.com/tips/email-phishing-scams-stop-method/)   

The second S.T.O.P. reminds users to follow the following instructions:   

- **S**low down. Do not panic. Take a pause. Scammers run on your adrenaline. 
- **T**ype the address yourself. Don’t use the message’s link. 
- **O**pen nothing unexpected. Verify first. 
- **P**rove the sender. Check the real From address/number, not just the display name. Remember to read once more!   

At times, "unsubscribe" links can be a trap to harvest legit emails. Check the link text before clicking.    
**Avoid** "Accept All" cookies on web browsers. Use functional cookies only or reject all, as options are available.    

---- 

## The One with LDAP 

To query and backup/dump the LDIF tree:    
```
ldapsearch -x -b "dc=iitx,dc=ac,dc=in" -H ldap://10.10.10.10 -D "cn=admin,dc=iitx,dc=ac,dc=in" -W > backup.ldif  
```
This can be useful to create another instance of LDAP. You should mention the root DN / domain name, LDAP server IP, and admin user.    

Sysad should practice and know LDAP-related [command line tools](https://docs.oracle.com/cd/A97630_01/network.920/a96579/comtools.htm) to query, add, delete, and modify LDAP entries. It's a different experience with the command line :) and you can write scripts to automate the housekeeping!    
**Lesson: Learn LDAP command line interface, it works, it's open source, it's powerful and convenient way once you start using them.**    

[Manage LDAP entries using LDAP Account Manager (LAM)](https://www.ldap-account-manager.org/lamcms/) and [Web-based LDAP Schema admin](http://phpldapadmin.sourceforge.net/wiki/index.php/Main_Page)   

---- 

## The One with RADIUS 

In network security, **AAA** is used as an abstraction for authentication, authorization, and accounting purposes concerning WPA2-Enterprise or 802.1x standard for security. RADIUS (Remote Access Dial-In User Service) promises to provide this gold security standard.    
To provide identity (IDP), RADIUS is often used with LDAP. This combination is definitely a fire for Sysad.   

Relevant posts:    
1. [Cloud Radius](https://www.cloudradius.com/ldap-vs-radius/)    
2. [OpenLDAP](https://wiki.freeradius.org/building/openldap), [FreeRadius setup](https://laravel-example.blogspot.com/2019/01/setup-freeradius-authentication-with.html) and [LAM](https://www.ldap-account-manager.org/static/doc/manual-onePage/index.html)   
[RADIUS - AAA](https://www.tutorialspoint.com/radius/aaa_and_nas.htm)     

---- 

PART-3    


## The One with Security 

Some [security-related primer](http://intronetworks.cs.luc.edu/current/html/security.html) and [SSH and TLS](http://intronetworks.cs.luc.edu/current/html/publickey.html#ssh-and-tls)   

Prof Wenliang Du's lab manual (Syracuse Univ) is one practical way to study, introduce, or teach security in labs.   

Note:- Safety and Security are two different aspects. No language is so poor to have two such words for the exact same meaning. For digital infrastructure, compute, and network - we discuss security aspects. We discuss safety aspects against fire, civil/electrical infrastructure, and natural calamity. Remember safety checks for fire, building, doors, accessibility, and security at the entrance gate, airports, and computer/mobile/network. 
Exception: In the context of formal verification of models, safety property asserts that a program execution does not reach a bad state.    

---- 

## The One with TLS Certificates   

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

**System upgrade: You may need to upgrade the Apache server to v2.4.38 or higher, OpenSSL to v1.1.1 or higher, and Ubuntu OS for TLS v1.3    

Notes:-    
* SSL/TLS Certificates are valid for a maximum of 398 days. You should take care of the time zone if the issuer is not in the same time zone as the host.    
* Paid TLS certificates do not use better cryptography than free certificates (e.g., Let's Encrypt). Paid TLS can give you extended validity on certificates.    
* Subject Alternate Name (SAN) or multi-domain TLS certificates allow additional host names to be protected by the same /single TLS certificate when creating the certificate.   
* Apache allows you to virtually host multiple HTTPS sites with a single public IP address using SAN certificates.    
* A wildcard certificate can protect all sub-domains of the same suffix top-level domain (TLD), e.g., *.mydomain.com - while for *.mydomain.org, you need a separate certificate.   
* SSL is only referred to for historical reasons. Most SSL/TLS certificates currently use TLS v1.2 / v1.3.   
* Web browsers have a hardcoded list of trusted certificate authorities (CA) to check that your certificate is signed by someone it trusts.   
* You can make a "self-signed" TLS certificate. Because a trusted certificate authority does not sign that certificate, browsers won't accept it.   

[List of Trusted Certifying Authorities](https://developer.visa.com/pages/trusted_certifying_authorities)    
[Chrome Root Store](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.md)   
[Mozilla Root Store]()    
[Common CA Database](https://www.ccadb.org/resources)    
[CCADB - Root Certificate List](https://ccadb.my.salesforce-sites.com/mozilla/IncludedRootCertificateReport)    

\citations for TLS notes: [1](https://questions.wizardzines.com/tls-certificates.html) and [2](https://www.digicert.com/faq/public-trust-and-certificates)   

[Sample X.509 certificate for public key exchange](https://github.com/rks101/egnet/blob/main/_.sendgrid.net) and [another example on Wikipedia](https://en.wikipedia.org/wiki/X.509#Sample_X.509_certificates)    

Decoded version of first X.509 certificate:   
```
Common Name: *.sendgrid.net

Subject Alternative Names (SANs):

*.sendgrid.net
sendgrid.net
Organization: N/A

Locality: N/A

State: N/A

Country: N/A

Valid From: 2022-12-14 18:12:57 UTC

Valid To: 2024-01-15 17:57:31 UTC

Issuer: Go Daddy Secure Certificate Authority - G2

Serial Number: 8BD03870C3B67FB8

Algorithm: sha256WithRSAEncryption

Key size: 2048
```

[Help: Generate a Certificate Signing Request](https://www.geocerts.com/support/generate-csr)    
[Help: Install SSL certificate](https://www.geocerts.com/support/install-ssl)    


----

Using `openssl` for SSL/TLS certificates    

e.g., check if a remote server uses TLSv1.2 - if you get the certificate chain back, it's all good.    
```
openssl s_client -connect server:port -tls1_2 
```
or use to get enabled TLS and ciphersuites:    
```
openssl s_client -connect server:443
openssl s_client -connect server:443 -ciphersuites TLS_AES_128_GCM_SHA256 
```
You can specify these values TLS after server:port are: -ssl3, -tls1, -tls1_1, -tls1_2, -tls1_3    


```
$ openssl s_client -connect eg.riit.ac.in:443 -tls1_2
CONNECTED(00000003)
depth=2 C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", CN = Go Daddy Root Certificate Authority - G2
verify return:1
depth=1 C = US, ST = Arizona, L = Scottsdale, O = "GoDaddy.com, Inc.", OU = http://certs.godaddy.com/repository/, CN = Go Daddy Secure Certificate Authority - G2
verify return:1
depth=0 CN = eg.riit.ac.in
verify return:1
---
**Certificate chain** 
 0 s:CN = eg.riit.ac.in
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
subject=CN = eg.riit.ac.in
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

## The One with Authentication 

Authentication is usually done for an account (that may be a user, device, or service) using either password/passphrase or a certificate file at client side.    

<details>
	<summary>Q. What is basic authentication?</summary>
	<p>
A. Basic authentication header was used in HTTP requests to provide a username and password as encoded string for authentication. It is formatted as Authorization: Basic <credentials>, where <credentials> is the Base64 encoding of the username and password joined by a colon (username:password). This text is only Base64 encoded string (containing A-Z,a-z,0-9,+,/,==) and no encryption is used.    
	</p>
</details>

<details>
	<summary>Q. What is 802.1x authentication?</summary>
	<p>
A. IEEE 802.1x is a standard for port-based network access control (P-NAC) for devices connecting to a LAN or wireless LAN (WLAN). 802.1x has three parties: Supplicant (a client/requester), Authenticator (Network device/access controller), and Authentication Server (RADIUS). [More gyan](https://en.wikipedia.org/wiki/IEEE_802.1X).     
Not all devices may support 802.1x such as printers, cameras, wireless/cordless phone, sensors, TV or smart displays.  		
	</p>
</details>

<details>
	<summary>Q. What is AAA server?</summary>
	<p>
A. Centralized Authentication, Authorization, and Accounting for user access to network resources.    		
	</p>
</details>      

<details>
	<summary>Q. What is eduroam?</summary>
	<p>
A. eduroam, an international wireless roaming service, mandates the use of 802.1X authentication when providing network access to guests/visitors visiting from other eduroam-enabled institutions. Users are authenticated with credentials from their home institution, regardless of the location of the eduroam access point. Authorization to access the Internet and other resources are handled by the visited institution. Users do not have to pay to use eduroam. This is as good as to see Prof Siva from IIT Bombay visiting CMI, Chennai or University of Illinois-UC, Chicago and using LDAP credentials from his home institution and feel as good as in home network (yes, with a VPN).     		
	</p>
</details>


[Security risks and alternatives of PEAP MSCHAPv2](https://securew2.com/blog/security-analysis-of-peap-mschapv2)      

[An argument for EAP-TLS v/s EAP-TTLS/PAP](https://securew2.com/blog/eap-tls-vs-eap-ttls-pap)     

<details>
	<summary>Terms</summary>
	<p>
EAP: Extensible Authentication Protocol     
TLS: Transport Layer Security (provides cryptographic guaranty/mechanism for secure communication over network)    
SSL: Secure Socket Layer (precursor to TLS)     
EAP-TLS: EAP-Transport Layer Security     
TTLS: Tunneled Transport Layer Security     
PAP: Password Authentication Protocol     
PEAP: Protected Extensible Authentication Protocol     
MS-CHAP: Microsoft Challenge-Handshake Authentication Protocol    
RADIUS: Remote Authentication Dial-In User Service (centralized AAA server)     		
	</p>
</details>

---- 

PART-4    


## QUIC 

QUIC (a transport layer protocol) can improve the performance of connection-oriented web applications (having sessions) by creating multi-plex UDP connections and eliminating TCP at the transport layer! [See reduced RTTs in handshake](https://en.wikipedia.org/wiki/File:Tcp-vs-quic-handshake.svg).    

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

## The One with Blocking IP 

Suppose your public IP is 14.139.53.130 or something like that, and you wish to check if this public IP of yours is blocked or not while you browse websites for information, and the page is not loading, it just tries and gives up.    

Reason for listing - Net 14.139.0.0/16 is UCEPROTECT-Level2 listed because 167 impacts are seen from NKN-CORE-NW NKN Core Network, IN/AS55824 there. See:
[UCE Protect Network](https://www.uceprotect.net/en/rblcheck.php?ipr=14.139.53.130) and check IP against the blocked IP list and any other recommendations.       

[My public IP](https://ipv4.icanhazip.com/), [link2](https://labs.sucuri.net/myip.php)      

[Why is your public IP is blocked](https://blog.sucuri.net/2023/06/why-your-ip-address-is-blocked-how-to-fix-it.html)     

[Is it blocked right now?](https://www.isitdownrightnow.com/iitjammu.ac.in.html)   

[Website Down or IP Blocked](https://dev.to/nemanja_falb_e0e451d06be0/access-blocked-vs-website-down-how-to-tell-the-difference-isp-firewall-geo-blocking-explained-7ip)    


----

## HPC    

High Performance Computing facility changes the game for computing requirements.   

[PARAM Rudra @ IITB](https://iitb-3f2330.gitlab.io/)     

[NSM India - PARAM series supercomputers and others](https://nsmindia.in/infrastructure/nsm-systems/)    

----

## The Privacy Conundrum    

From l0pht testifying in court in 1999, to modern-day light robbery of our personal data by mobile Apps, to the desire to automate and integrate everything into one identifier - there are several daily activities and attack surfaces wherein our data privacy is at stake.   

More information can be found on my repository [isdp](https://github.com/rks101/isdp)     

----

## History bytes 

[Kanwal Rekhi founded Excelan in 1982, which commercialized Ethernet](https://historyofcomputercommunications.info/interviews/Kanwal-Rekhi/)    

[Circuits Packets and Protocols - 1968-1988](https://circuitspacketsandprotocols.com/)   

----

## Movies 

[The Warriors of the Net](https://www.youtube.com/watch?v=RhvKm0RdUY0)    
[lopht - 7 hackers testifying at US Senate](https://www.youtube.com/watch?v=VVJldn_MmMY)    
[How Internet works via submarine cables](https://www.youtube.com/watch?v=6epiGBMXBDs)     
[How OFC carry light?](https://www.youtube.com/watch?v=G1Ke-H8I1uk)    




---- 
