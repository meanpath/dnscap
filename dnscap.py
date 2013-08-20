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

def usage():
    print 'dnscap'
    print 'forward dns query packets to riemann for visualisation'
    print 'Usage: '
    print sys.argv[0] + ' <pcapfile>'
    sys.exit()

class PacketLog:
    def __init__(self, riemann):
        self.riemann=riemann
        self.host = gethostname()
        self.reset()

    def reset(self):
        self.timing = {}
        self.orphans = 0
        self.queries = {}

    def addEvent(self,es,service, metric):
        es.append(bernhard.Event(params={'host': self.host, 'service': service, 'metric': metric}))

    def flush(self):
        ts = flatten([x for x in self.timing.values()])
        avg = 1000 * sum(ts) / len(ts)
        es=[]
        self.addEvent(es,'dns_average', avg)
        self.addEvent(es,'dns_max', 1000* max(ts))
        self.addEvent(es,'dns_count', len(ts))
        self.addEvent(es,'dns_orphans', self.orphans)

        msg = bernhard.Message(events=es)
        self.riemann.transmit(msg)


    def process_packet(self,packet):
        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        if packet.haslayer(DNSRR):
            r = packet[DNSRR]
            try:
                [query, oldtime] = self.queries.pop(dns.id)
                # FIX check query name is the same too
                if query.qname not in self.timing:
                    self.timing[query.qname] = []

                self.timing[query.qname].append(packet.time - oldtime)
            except KeyError:
                # either someone is sending us fake responses
                # or we have duplicates
                self.orphans = self.orphans + 1
        elif packet.haslayer(DNSQR):
            q=packet[DNSQR]
            self.queries[dns.id] = [q, packet.time]


class Feeder:
    def __init__(self,reader, logger):
        self.reader=reader
        self.logger=logger
        self.reset_clearance()

    def reset_clearance(self):
        self.next_clearance = datetime.now() + timedelta(seconds=1)

    def loop(self):

        for packet in self.reader:
            if datetime.now() > self.next_clearance:
                self.reset_clearance()
                self.logger.flush()
            self.logger.process_packet(packet)
        self.logger.flush()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    # in our use case this is often a FIFO
    host = os.environ['RIEMANN_HOST']
    pcapdata = PcapReader(sys.argv[1])
    riemann = bernhard.Client(host=host, transport=bernhard.UDPTransport)
    packetlog = PacketLog(riemann)
    feeder = Feeder(pcapdata, packetlog)
    feeder.loop()
