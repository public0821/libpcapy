from libpcapy import pcap
import signal
import argparse
import sys
import threading

counter = 0

def handler(signum, frame):
    print('Signal handler called with signal ', signum, counter)
    sys.exit(0)

def callback(pkthdr, data, user_data):
    global counter
    counter += 1
    print('%d.%d(%d/%d) '%(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen, pkthdr.len), data)

signal.signal(signal.SIGINT, handler)

def tcpdump():
    parser = argparse.ArgumentParser(description='tcpdump')
    #parser.add_argument('filter', type=str, help="Specifies filter")
    parser.add_argument('-i', metavar='interface', dest='interface', required=True, type=str, help="Specifies the interface listen on")
    args = parser.parse_args()
    
    try:
        index = int(args.interface)
    except ValueError:
        device = args.interface
    else:   
        dev_names = []
        alldevs = pcap.pcap_findalldevs()
        dev = alldevs 
        while True:
            if not dev:
                break
            dev_names.append(dev.contents.name.decode())
            dev = dev.contents.next
        device = dev_names[index]
        pcap.pcap_freealldevs(alldevs)
    
    hpcap = pcap.pcap_open_live(device, 65535, False, 0)
    pf = pcap.pcap_compile(hpcap, 'icmp', False, 0)
    #pcap.pcap_setfilter(hpcap, pf)
#    #pcap.pcap_freecode(pf)
    pcap.pcap_loop(hpcap, -1, callback, None)

if __name__ == '__main__':
    t = threading.Thread(target=tcpdump)
    t.daemon = True
    t.start()
    t.join()
