'''
ptypes.py contains types, structures and constants both in libpcap and winpcap
'''
from ctypes import *
import sys

#use man pcap-linktype or visit http://www.tcpdump.org/linktypes.html for detail
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_AX25 = 3    
LINKTYPE_IEEE802_5 = 6
LINKTYPE_ARCNET_BSD = 7    
LINKTYPE_SLIP = 8    
LINKTYPE_PPP = 9
LINKTYPE_FDDI = 10    
LINKTYPE_PPP_HDLC = 50    
LINKTYPE_PPP_ETHER = 51
LINKTYPE_ATM_RFC1483 = 100    
LINKTYPE_RAW = 101    
LINKTYPE_C_HDLC = 104
LINKTYPE_IEEE802_11 = 105    
LINKTYPE_FRELAY = 107    
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113    
LINKTYPE_LTALK = 114    
LINKTYPE_PFLOG = 117
LINKTYPE_IEEE802_11_PRISM = 119    
LINKTYPE_IP_OVER_FC = 122    
LINKTYPE_SUNATM = 123    
LINKTYPE_IEEE802_11_RADIOTAP = 127    
LINKTYPE_ARCNET_LINUX = 129    
LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138    
LINKTYPE_MTP2_WITH_PHDR = 139    
LINKTYPE_MTP2 = 140    
LINKTYPE_MTP3 = 141
LINKTYPE_SCCP = 142    
LINKTYPE_DOCSIS = 143    
LINKTYPE_LINUX_IRDA = 144    
#LINKTYPE_USER0-LINKTYPE-USER15    147-162    DLT_USER0-DLT_USER15     Reserved for private use; see above.
LINKTYPE_IEEE802_11_AVS = 163    
LINKTYPE_BACNET_MS_TP = 165
LINKTYPE_PPP_PPPD = 166    
LINKTYPE_GPRS_LLC = 169
LINKTYPE_LINUX_LAPD = 177    
LINKTYPE_BLUETOOTH_HCI_H4 = 187    
LINKTYPE_USB_LINUX = 189    
LINKTYPE_PPI = 192    
LINKTYPE_IEEE802_15_4 = 195    
LINKTYPE_SITA = 196    
LINKTYPE_ERF = 197
LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201    
LINKTYPE_AX25_KISS = 202    
LINKTYPE_LAPD = 203    
LINKTYPE_PPP_WITH_DIR = 204    
LINKTYPE_C_HDLC_WITH_DIR = 205    
LINKTYPE_FRELAY_WITH_DIR = 206    
LINKTYPE_IPMB_LINUX = 209    
LINKTYPE_IEEE802_15_4_NONASK_PHY = 215    
LINKTYPE_USB_LINUX_MMAPPED = 220    
LINKTYPE_FC_2 = 224    
LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225    
LINKTYPE_IPNET = 226    
LINKTYPE_CAN_SOCKETCAN = 227    
LINKTYPE_IPV4 = 228    
LINKTYPE_IPV6 = 229
LINKTYPE_IEEE802_15_4_NOFCS = 230    
LINKTYPE_DBUS = 231    
LINKTYPE_DVB_CI = 235
LINKTYPE_MUX27010 = 236    
LINKTYPE_STANAG_5066_D_PDU = 237    
LINKTYPE_NFLOG = 239    
LINKTYPE_NETANALYZER = 240    
LINKTYPE_NETANALYZER_TRANSPARENT = 241
LINKTYPE_IPOIB = 242    
LINKTYPE_MPEG_2_TS = 243    
LINKTYPE_NG40 = 244    
LINKTYPE_NFC_LLCP = 245    
LINKTYPE_INFINIBAND = 247
LINKTYPE_SCTP = 248    
LINKTYPE_USBPCAP = 249    
LINKTYPE_RTAC_SERIAL = 250    
LINKTYPE_BLUETOOTH_LE_LL = 251    

PCAP_ERRBUF_SIZE = 256
c_uint32_p = POINTER(c_uint32)
c_ubyte_p = POINTER(c_ubyte)
c_int_p = POINTER(c_int)

class pcap_t(Structure):
    pass

pcap_t_p = POINTER(pcap_t)

class pcap_dumper_t(Structure):
    pass

pcap_dumper_t_p = POINTER(pcap_dumper_t)

class timeval(Structure):
    _fields_ = [
        ('tv_sec', c_long),
        ('tv_usec', c_long)
    ]

class pcap_pkthdr(Structure):
    if sys.platform == 'darwin':
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32),
            ('comments', (c_char * 256))
        ]
    else:
        _fields_ = [
            ('ts', timeval),
            ('caplen', c_uint32),
            ('len', c_uint32)
        ]
pcap_pkthdr_p = POINTER(pcap_pkthdr)

class bpf_insn(Structure):
    _fields_ = [
        ('code', c_ushort),
        ('jt', c_ubyte),
        ('jf', c_ubyte),
        ('k', c_uint32)
    ]
bpf_insn_p = POINTER(bpf_insn)

class bpf_program(Structure):
    _fields_ = [
        ('bf_len', c_uint),
        ('bf_insns', bpf_insn_p)
    ] 

bpf_program_p = POINTER(bpf_program)


class sockaddr_in(Structure):
    _pack_ = 1
    if sys.platform == 'darwin':
        _fields_ = [
            ('sin_len', c_ubyte),
            ('sin_family', c_ubyte),
            ('sin_port', c_ushort),
            ('sin_addr', c_uint32),
            ('sin_zero', c_ubyte * 8)
        ]
    else:
        _fields_ = [
            ('sin_family', c_ushort),
            ('sin_port', c_ushort),
            ('sin_addr', c_uint32),
            ('sin_zero', c_ubyte * 8)
        ]


class sockaddr_in6(Structure):
    _pack_ = 1
    if sys.platform == 'darwin':
        _fields_ = [
            ('sin6_len', c_ubyte),
            ('sin6_family', c_ubyte),
            ('sin6_port', c_ushort),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_ubyte * 16),
            ('sin6_scope_id', c_uint32)
        ]
    else:
        _fields_ = [
            ('sin6_family', c_ushort),
            ('sin6_port', c_ushort),
            ('sin6_flowinfo', c_uint32),
            ('sin6_addr', c_ubyte * 16),
            ('sin6_scope_id', c_uint32)
        ]


class sockaddr_sa(Structure):
    _pack_ = 1
    if sys.platform == 'darwin':
        _fields_ = [
            ('sa_len', c_ubyte),
            ('sa_family', c_ubyte),
            ('sa_data', c_char * 14)
        ]
    else:
        _fields_ = [
            ('sa_family', c_ushort),
            ('sa_data', c_char * 14)
        ]


class sockaddr_dl(Structure):
    _pack_ = 1
    _fields_ = (
        ('sdl_len', c_ubyte),
        ('sdl_family', c_ubyte),
        ('sdl_index', c_ushort),
        ('sdl_type', c_ubyte),
        ('sdl_nlen', c_ubyte),
        ('sdl_alen', c_ubyte),
        ('sdl_slen', c_ubyte),
        ('sdl_data', (c_ubyte * 12)),
    )

class sockaddr_ll(Structure):
    _pack_ = 1
    _fields_ = (
        ('sll_family', c_ushort),
        ('sll_protocol', c_ushort),
        ('sll_ifindex', c_int),
        ('sll_hatype', c_ushort),
        ('sll_pkttype', c_ubyte),
        ('sll_halen', c_ubyte),
        ('sll_data', (c_ubyte * 8)),
    )


class sockaddr(Union):
    _pack_ = 1
    _fields_ = [
        ('sa', sockaddr_sa),
        ('sin', sockaddr_in),
        ('sin6', sockaddr_in6),
        ('sdl', sockaddr_dl),
        ('sll', sockaddr_ll),
    ]


sockaddr_p = POINTER(sockaddr)


class pcap_addr_t(Structure):
    _pack_ = 1


pcap_addr_t_p = POINTER(pcap_addr_t)


pcap_addr_t._fields_ = [
    ('next', pcap_addr_t_p),
    ('addr', sockaddr_p),
    ('netmask', sockaddr_p),
    ('broadaddr', sockaddr_p),
    ('dstaddr', sockaddr_p)
]

class pcap_if_t(Structure):
    _pack_ = 1
    
pcap_if_t_p = POINTER(pcap_if_t)

pcap_if_t._fields_ = [
        ('next', pcap_if_t_p),
        ('name', c_char_p),
        ('description', c_char_p),
        ('addresses', pcap_addr_t_p),
        ('flags', c_uint)
    ]


class pcap_stat(Structure):
    if sys.platform == 'win32':
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint),
            ('bs_capt', c_uint)
            #Win32 specific. number of packets captured, i.e number of packets that are accepted by the filter, 
            #that find place in the kernel buffer and therefore that actually reach the application. 
            #For backward compatibility, pcap_stats() does not fill this member, so use pcap_stats_ex() to get it. 
        ]
    else:
        _fields_ = [
            ('ps_recv', c_uint),
            ('ps_drop', c_uint),
            ('ps_ifdrop', c_uint)
        ]

pcap_stat_p = POINTER(pcap_stat)
