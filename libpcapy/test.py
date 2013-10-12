from libpcapy import libpcap, pcap, ptypes
import sys
import time
import unittest

device = None
dump_data = (b'11111111122222', b'333333333333333333333333333333333333333334444')

class TestPcap(unittest.TestCase):
    hpcap = None
    
    @classmethod
    def setUpClass(cls): 
        cls.hpcap = pcap.pcap_open_live(device, 65535, True, 0)
        
    @classmethod
    def tearDownClass(cls):
        pcap.pcap_close(cls.hpcap)

    def test_pcap_lookupdev(self):
        self.assertNotEqual(len(pcap.pcap_lookupdev()), 0)

    def test_pcap_lookupnet(self):
        pcap.pcap_lookupnet(device) 
    
    def test_pcap_lib_version(self):
        self.assertNotEqual(len(pcap.pcap_lib_version()), 0)
        
    def test_pcap_major_version(self):
        self.assertGreaterEqual(pcap.pcap_major_version(self.hpcap), 0)
        
    def test_pcap_minor_version(self):
        self.assertGreaterEqual(pcap.pcap_minor_version(self.hpcap), 0)
        
    def test_pcap_sendpacket(self):
        pcap.pcap_sendpacket(self.hpcap, b'datadatadatatdatadafjasdkfjkasjdfkasdfklajsdfjlksaflsjkfjaskdjfasjfdk')
        
    def test_pcap_list_datalinks(self):
        self.assertNotEqual(len(pcap.pcap_list_datalinks(self.hpcap)), 0)
        
    def test_pcap_datalink(self):
        self.assertGreaterEqual(pcap.pcap_datalink(self.hpcap), 0)
        
    def test_pcap_set_datalink(self):
        pass    #TODO
#         pcap.pcap_set_datalink(self.hpcap, ptypes.LINKTYPE_IPV4)
        
    def test_pcap_datalink_val_to_name(self):
        self.assertNotEqual(len(pcap.pcap_datalink_val_to_name(ptypes.LINKTYPE_ETHERNET)), 0)
        
    def test_pcap_datalink_val_to_descriptione(self):
        self.assertNotEqual(len(pcap.pcap_datalink_val_to_description(ptypes.LINKTYPE_ETHERNET)), 0)
    
    def test_pcap_datalink_name_to_val(self):
        self.assertEqual(pcap.pcap_datalink_name_to_val('NULL'), ptypes.LINKTYPE_NULL)
         
    def test_pcap_stats(self):
        pass    #TODO
    
    def test_pcap_is_swapped(self):
        pcap.pcap_is_swapped(self.hpcap)
        
    def test_pcap_snapshot(self):
        self.assertGreaterEqual(pcap.pcap_snapshot(self.hpcap), 0)
        
    def test_pcap_setnonblock(self):
        pcap.pcap_setnonblock(self.hpcap, False)
        self.assertEqual(pcap.pcap_getnonblock(self.hpcap), False)
        pcap.pcap_setnonblock(self.hpcap, True)
        self.assertEqual(pcap.pcap_getnonblock(self.hpcap), True)
    
    def test_pcap_setfilter(self):
        pf = pcap.pcap_compile(self.hpcap, 'icmp', True, 0)
        pcap.pcap_setfilter(self.hpcap, pf)
        pcap.pcap_freecode(pf)
        
    def test_pcap_compile_nopcap(self):
        pf = pcap.pcap_compile_nopcap(64, ptypes.LINKTYPE_ETHERNET, 'icmp', True, 0)
        pcap.pcap_freecode(pf)
        
    
class TestPcapReadOffline(unittest.TestCase):
    hpcap = None
    
    def setUp(self): 
        self.hpcap = pcap.pcap_open_offline('./test.pcap')
        
    def tearDown(self):
        pcap.pcap_close(self.hpcap)
        self.hpcap = None

    def test_pcap_next(self):
        for data in dump_data:
            (pkthdr, packet) = pcap.pcap_next(self.hpcap)
            self.assertEqual(packet, data) 
            self.assertEqual(pkthdr.caplen, pkthdr.len)
            self.assertEqual(pkthdr.caplen, len(data))
            

    def test_pcap_netx_ex(self):
        for data in dump_data:
            (pkthdr, packet) = pcap.pcap_next_ex(self.hpcap)
            self.assertEqual(packet, data) 
            self.assertEqual(pkthdr.caplen, pkthdr.len)
            self.assertEqual(pkthdr.caplen, len(data))
        
    def test_pcap_loop(self):
        self.dump_data_index = 0
        pcap.pcap_loop(self.hpcap, len(dump_data), TestPcapReadOffline.callback, self)
        
    def test_pcap_dispatch(self):
        self.dump_data_index = 0
        pcap.pcap_dispatch(self.hpcap, len(dump_data), TestPcapReadOffline.callback, self)
            
    @staticmethod       
    def callback(pkthdr, data, user_data):
        self = user_data
        packet = dump_data[self.dump_data_index]
        self.dump_data_index += 1
        self.assertEqual(packet, data) 
        self.assertEqual(pkthdr.caplen, pkthdr.len)
        self.assertEqual(pkthdr.caplen, len(data))
        
class TestPcapDump(unittest.TestCase):
    hpcap = None
    pdumper = None
    
    @classmethod
    def setUpClass(cls): 
        #cls.hpcap = pcap.pcap_open_live(device, 65535, True, 0)
        cls.hpcap = pcap.pcap_open_dead(ptypes.LINKTYPE_ETHERNET, 65535)
        cls.pdumper = pcap.pcap_dump_open(cls.hpcap, './test.pcap')
        
    @classmethod
    def tearDownClass(cls):
        pcap.pcap_dump_flush(cls.pdumper)
        pcap.pcap_dump_close(cls.pdumper)
        pcap.pcap_close(cls.hpcap)

    def test_pcap_dump(self):
        total_len = 24 #sizeof(sturct pcap_file_header)
        pkthdr_len = 16 #sizeof(struct pcap_pkthdr)
        for data in dump_data:
            pkthdr = ptypes.pcap_pkthdr()
            pkthdr_p = ptypes.pcap_pkthdr_p(pkthdr)
            pkthdr.caplen = len(data)
            pkthdr.len = len(data)
            now = time.time()
            pkthdr.ts.tv_sec = int(now)
            pkthdr.ts.tv_usec = int(now * 1000 * 1000)%(1000*1000)
            pcap.pcap_dump (self.pdumper, pkthdr_p, data)
            ft = pcap.pcap_dump_ftell(self.pdumper)
            self.assertEqual(total_len + len(data) + pkthdr_len, ft) 
            total_len += len(data) + pkthdr_len
       
# class TestLibPcap(unittest.TestCase):
#     hpcap = None
#     
#     @classmethod
#     def setUpClass(cls): 
#         cls.hpcap = libpcap.pcap_create(device)
# 
#     @classmethod
#     def tearDownClass(cls):
#         pass
# 
#     def test_pcap_create(self):
#         libpcap.pcap_create(device)
# 
#     def test_pcap_set_snaplen(self):
#         libpcap.pcap_set_snaplen(self.hpcap, 1024)
# 
#     def test_pcap_set_promisc(self):
#         libpcap.pcap_set_promisc(self.hpcap, False)
#         libpcap.pcap_set_promisc(self.hpcap, True)
# 
#     def test_pcap_set_rfmon(self):
#         can_set_rfmon = libpcap.pcap_can_set_rfmon(self.hpcap)
#         if can_set_rfmon:
#             libpcap.pcap_set_rfmon(self.hpcap, False)
#             libpcap.pcap_set_rfmon(self.hpcap, True)
# 
#     def test_pcap_set_timeout(self):
#         libpcap.pcap_set_timeout(self.hpcap, 1000*100)
# 
#     def test_pcap_set_buffer_size(self):
#         libpcap.pcap_set_buffer_size(self.hpcap, 1024*1024*1024)


if __name__ == '__main__':
    dev_names = []
    alldevs = pcap.pcap_findalldevs()
    dev = alldevs 
    while True:
        if not dev:
            break
        dev_names.append(dev.contents.name.decode())
        print(len(dev_names)-1, dev_names[-1])
        dev = dev.contents.next
    interface = input('which interface will be used for test? ')
    try:
        index = int(interface)
    except ValueError:
        print('error:should input the index of interface')
        sys.exit(-1)
    device = dev_names[index]
    pcap.pcap_freealldevs(alldevs)
    unittest.main()
    
