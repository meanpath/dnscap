#!/usr/bin/env python
#DiabloHorn http://diablohorn.wordpress.com

import sys
import md5
from compiler.ast import flatten
from datetime import datetime,timedelta
#http://stackoverflow.com/questions/13249341/surpress-scapy-warning-message-when-importing-the-module
import logging
import bernhard
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import os


riemann = bernhard.Client(host=os.getenv('RIEMANN_HOST'), transport=bernhard.UDPTransport)

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

from socket import gethostname


host = gethostname()

def usage():
    print 'DiabloHorn http://diablohorn.wordpress.com'
    print 'verify nmap scans, find delayed responses'
    print 'Usage: '
    print sys.argv[0] + ' <pcapfile> <threshold>'
    print 'Ex: '
    print sys.argv[0] + ' delayedresponse.pcap 0.8'
    print '[timestamp] [difference] [src ip] [dst ip] [dst port] [response flags]'
    print '1367887784.231386 5.00098395348 10.50.0.107 10.50.0.103 22 [\'SYN\', \'ACK\']'
    sys.exit()

def gethash(data):
    return md5.new(data).hexdigest()

def flush(timing,orphan):
    events = []
    ts = flatten([x for x in timing.values()])
    avg = sum(ts) / len(ts)
    events.append(bernhard.Event(params={'host': host, 'service': 'dns_average', 'metric': (sum(ts)/len(ts))}))
    events.append(bernhard.Event(params={'host': host, 'service': 'dns_max', 'metric': max(ts)}))
    events.append(bernhard.Event(params={'host': host, 'service': 'dns_count', 'metric': len(ts)}))
    events.append(bernhard.Event(params={'host': host, 'service': 'dns_orphans', 'metric': orphans}))

    riemann.transmit(bernhard.Message(events=events))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        usage()
    queries = {}
    timing = {}
    orphans = 0
    #should enable us to read large files
    pcapdata = PcapReader(sys.argv[1])
    print queries
    print timing
    next_clearance = datetime.now() + timedelta(seconds=1)
    for packet in pcapdata:
        now = datetime.now()
        if now > next_clearance:
            next_clearance = datetime.now() + timedelta(seconds=1)
            flush(timing,orphans)
            orphans = 0
            for k in timing.keys():
                del(timing[k])



        if packet.haslayer(DNS):
            dns = packet[DNS]
            print packet[IP].time
            print dns.id
            if packet.haslayer(DNSRR):
                r = packet[DNSRR]
                print "it's a response: " + str(packet[DNS].id)
                try:
                    [query, oldtime] = queries.pop(dns.id)
                    # FIX check query name is the same too
                    if query.qname not in timing:
                        timing[query.qname] = []

                    timing[query.qname].append(packet[IP].time - oldtime)
                    # times[
                except KeyError:
                        # either someone is sending us fake responses
                        # or we have duplicates
                    orphans = orphans + 1

            elif packet.haslayer(DNSQR):
                q=packet[DNSQR]
                queries[dns.id] = [q, packet[IP].time]
                print "it's a query: " + packet[DNSQR].qname
                print packet[DNSQR].fields

    print "finished"

    for k in queries.keys():
        print "no response for "
        print [k,queries[v]]

    flush(timing,orphans)
