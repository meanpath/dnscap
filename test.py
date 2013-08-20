import unittest
import dnscap
from scapy.all import PcapReader

class MockRiemann:
    def __init__(self):
        self.messages = []
    def transmit(self,message):
        self.messages.append(message)

class TestPcapReader(unittest.TestCase):
    def testReader(self):
        data1 = PcapReader("./dns1.pcap")
        l1 = [i for i in data1]
        data2 = PcapReader("./dns1.pcap")
        l2 = [i for i in data2]
        self.assertEqual(l1,l2)

class TestPacketLog(unittest.TestCase):
    def setUp(self):
        self.riemann = MockRiemann()
        self.packetlog = dnscap.PacketLog(self.riemann)

    def testLog(self):
        data = PcapReader("./dns1.pcap")
        feeder = dnscap.Feeder(data, self.packetlog)
        feeder.loop()
        events = [[e.metric,e.service] for m in self.riemann.messages for e in m.events]
	rec = [[0.01802176899380154, 'dns_average'], [0.03196001052856445, 'dns_max'], [9, 'dns_count'], [0, 'dns_orphans']]
        self.assertEqual(events, rec)


if __name__ == '__main__':
    unittest.main()
