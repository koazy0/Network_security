#!usrbinpython
from scapy.all import *

user		="172.17.0.2"
DNS_server	="172.17.0.3"
attacker	="172.17.0.1"
host		="192.168.62.19"


def GenerateQueryPacket():
	targetName='abcde.example.com' #abcde为随意设定,后续会修改
	IPpkt=IP(dst=DNS_server,src=attacker) #dstDNS server IP --- srcattacker IP
	UDPpkt=UDP(dport=53, sport=33333 , chksum=0 )#源端口可以任意设置
	Qdsec=DNSQR(qname=targetName)
	DNSpkt=DNS(id=0xaaaa, qr=0, qdcount=1,ancount=0,nscount=0,arcount=0,qd=Qdsec)
	Querypkt=IPpkt/UDPpkt/DNSpkt
	# Save the packet data to a file
	with open('Query.bin', 'wb') as f:
		f.write(bytes(Querypkt))
GenerateQueryPacket()
