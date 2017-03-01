#!/usr/bin/env python

import sys
from scapy.all import *
conf.verb = 0

source = sys.argv[1]
target = sys.argv[2]

#Generate random number for source port
Port = RandNum(1024, 65535)
#scan 10 well known ports
p1 = IP(dst=target, src=source) / TCP(dport= [21, 22, 23, 25, 53, 80, 110, 143, 179, 443], sport=Port,flags='FPU')
#capture response using sr
answer, unanswered =sr(p1, inter = RandNum(0,5), timeout = 10)
#show packets sent
print "this packet was sent: "
p1.show()
#show the results
print "Results: "
#if the ports responded they are closed, so all ports in answer are closed
print "These ports answered, so they are closed"
answer.summary()
#if the ports did not respond they are open, so all ports in unanswered are open
print "These ports did not answer, so they are open"
unanswered.summary()



sys.exit(0)
