from libpcapy import pcap, ptypes
import sys
import time

device = 'en0'

def send():
    hpcap = pcap.pcap_open_live(device, 65535, True, 0)
    pcap.pcap_sendpacket(hpcap, b'datadatadatatdatadafjasdkfjkasjdfkasdfklajsdfjlksaflsjkfjaskdjfasjfdk') 
    pcap.pcap_close(hpcap)    
    
def callback(pkthdr, data, user_data):
    print('%d.%d(%d/%d) '%(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen, pkthdr.len), data)
    
def capture():
    hpcap = pcap.pcap_open_live(device, 65535, True, 0)
    pcap.pcap_loop(hpcap, -1, callback, None)
    pcap.pcap_close(hpcap)  
        
def read():
    hpcap = pcap.pcap_open_offline('./test.pcap')
    while True:
        (pkthdr, packet) = pcap.pcap_next(hpcap)
        if pkthdr is None:
            break
        print(pkthdr.caplen, pkthdr.len, packet)
            
    pcap.pcap_close(hpcap)
    
def dump():
    hpcap = pcap.pcap_open_dead(ptypes.LINKTYPE_ETHERNET, 65535)
    pdumper = pcap.pcap_dump_open(hpcap, './test.pcap')
    
    data = b'11111111111111111111111111111111111111111111'
    pkthdr = ptypes.pcap_pkthdr()
    pkthdr.caplen = len(data)
    pkthdr.len = len(data)
    now = time.time()
    pkthdr.ts.tv_sec = int(now)
    pkthdr.ts.tv_usec = int(now * 1000 * 1000)%(1000*1000)
    pcap.pcap_dump(pdumper, ptypes.pcap_pkthdr_p(pkthdr), data)
    
    pcap.pcap_dump_flush(pdumper)
    pcap.pcap_dump_close(pdumper)
    pcap.pcap_close(hpcap)


if __name__ == '__main__':
    dump()
    read()
    send()
    capture()
    
