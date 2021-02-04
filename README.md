# egnet
egnet => easy net shows tools or utilities for debugging and troubleshooting network


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

View and manage Wireless network settings, similar to ifconfig for wireless  
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

One line webserver => a great and simplest way to show files from a directory  
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

----

