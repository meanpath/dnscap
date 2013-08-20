#!/usr/bin/env python
# based in part on
# http://diablohorn.wordpress.com/2010/12/05/dnscat-traffic-post-dissector/

import sys
from compiler.ast import flatten
from datetime import datetime,timedelta

import logging
import bernhard
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os
from socket import gethostname



try:
    #use this if the other line doesn't work
    from scapy import *
    from scapy.all import *
    from scapy.layers.dns import *
    from scapy.error import *
except:
    print 'You need to install python-scapy'
    sys.exit()

conf.verb = 0

host = gethostname()

def usage():
    print 'dnscap'
    print 'forward dns query packets to riemann for visualisation'
    print 'Usage: '
    print sys.argv[0] + ' <pcapfile>'
    sys.exit()

class PacketLog:
    def __init__(self, riemann):
        self.riemann=riemann
        self.reset()

    def reset():
        self.timing = {}
        self.orphans = 0
        self.queries = {}

    def flush():
        events = []
        ts = flatten([x for x in self.timing.values()])
        avg = sum(ts) / len(ts)
        events.append(bernhard.Event(params={'host': host, 'service': 'dns_average', 'metric': (sum(ts)/len(ts))}))
        events.append(bernhard.Event(params={'host': host, 'service': 'dns_max', 'metric': max(ts)}))
        events.append(bernhard.Event(params={'host': host, 'service': 'dns_count', 'metric': len(ts)}))
        events.append(bernhard.Event(params={'host': host, 'service': 'dns_orphans', 'metric': orphans}))

        riemann.transmit(bernhard.Message(events=events))



    def process_packet(packet):
        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        print packet[IP].time
        print dns.id
        if packet.haslayer(DNSRR):
            r = packet[DNSRR]
            print "it's a response: " + str(packet[DNS].id)
            try:
                [query, oldtime] = self.queries.pop(dns.id)
                # FIX check query name is the same too
                if query.qname not in timing:
                    self.timing[query.qname] = []

                self.timing[query.qname].append(packet[IP].time - oldtime)
            except KeyError:
                # either someone is sending us fake responses
                # or we have duplicates
                self.orphans = self.orphans + 1
        elif packet.haslayer(DNSQR):
            q=packet[DNSQR]
            self.queries[dns.id] = [q, packet[IP].time]
            print "it's a query: " + packet[DNSQR].qname
            print self.packet[DNSQR].fields


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    # in our use case this is often a FIFO
    pcapdata = PcapReader(sys.argv[1])
    next_clearance = datetime.now() + timedelta(seconds=1)
    riemann = bernhard.Client(host=os.getenv('RIEMANN_HOST'), transport=bernhard.UDPTransport)
    packetlog = new PacketLog(riemann)

    for packet in pcapdata:
        now = datetime.now()
        if now > next_clearance:
            next_clearance = datetime.now() + timedelta(seconds=1)
            packetlog.flush()
        packetlog.process_packet(packet)



    print "finished"

    for k in queries.keys():
        print "no response for "
        print [k,queries[v]]

    packetlog.flush()
