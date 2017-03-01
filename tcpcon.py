#!/usr/bin/env python

import sys
from scapy.all import *
conf.verb = 0

#get source and target ip
source = sys.argv[1]
target = sys.argv[2]

#Generate random number for source port
srcPort = RandNum(1024, 65535)
#pick 10 well known ports and scan them
p1 = IP(dst=target, src=source) / TCP(dport = [21, 22, 23, 25, 53, 80, 110, 143, 179, 443], sport = srcPort, flags='S')
#capture results using sr
answered, unanswered =sr(p1, inter = RandNum(0,5))
#show packet sent
print "this packet was sent: "
p1.show()
#show the reply
print " this was the reply: "
#print raw data
answered.summary()
#print using lambda filter for open connections
print answered.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") == "SA", prn=lambda(s,r): r.sprintf("The %TCP.sport% is open"))
#print using lambda filter for closed connections
print answered.summary(lfilter = lambda (s,r): r.sprintf("%TCP.flags%") != "SA", prn=lambda(s,r): r.sprintf("The %TCP.sport% is closed"))

sys.exit(0)
