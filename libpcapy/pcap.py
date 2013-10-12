'''
pcap.py contains all the function both in libpcap and winpcap
'''

from ctypes import *
from ctypes.util import find_library
from libpcapy.ptypes import PCAP_ERRBUF_SIZE, c_uint32_p, pcap_t_p, \
    pcap_dumper_t_p, c_ubyte_p, pcap_pkthdr_p, pcap_pkthdr, bpf_program_p, \
    bpf_program, pcap_if_t_p, pcap_stat, c_int_p
import sys

class PcapException(Exception):
    pass

class PcapError(PcapException):
    def __init__(self, info, code=-1):
        self.code = code
        super(PcapError, self).__init__(info)

class PcapWarning(PcapException):
    def __init__(self, info, code=-1):
        self.code = code
        super(PcapWarning, self).__init__(info)
       
if sys.platform == 'win32':
    libpath = find_library('wpcap')
else:
    libpath = find_library('pcap')
if not libpath:
   raise  PcapException("Can't find pcap library")
_pcap = cdll.LoadLibrary(libpath)   

def pcap_geterr(hpcap):
    '''return the error text pertaining to the last pcap library error.
    '''
    _pcap.pcap_geterr.restype = c_char_p
    return _pcap.pcap_geterr(hpcap).decode()     
 
        
def pcap_lookupdev():
    ''' Return the first valid device in the system.

    Deprecated:
        Use pcap_findalldevs() instead.

    pcap_lookupdev() returns a network device suitable for use with pcap_open_live() and pcap_lookupnet().
    '''
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    _pcap.pcap_lookupdev.restype = c_char_p
    device = _pcap.pcap_lookupdev(errbuf)
    if device:
        return device.decode()
    else:
        raise PcapError(errbuf.raw.decode())

def pcap_lookupnet(device):
    ''' Return the subnet and netmask of an interface.

    Deprecated:
        Use pcap_findalldevs() instead.
    
    pcap_lookupnet() is used to determine the network number and mask associated with the network device. 
    '''
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    netp = c_uint32_p(c_uint32(0))
    maskp = c_uint32_p(c_uint32(0))
    ret = _pcap.pcap_lookupnet(device.encode(), netp, maskp, errbuf)
    if ret == 0:
        return (netp.contents, maskp.contents)
    else:
        raise PcapError(errbuf.raw.decode())

def pcap_open_live(device, snaplen, promisc, to_ms, ignore_warn=True):
    '''Open a live capture from the network.

    pcap_open_live() is used to obtain a packet capture descriptor to look at packets on the network. 
    if pcap_open_live() fails, raise a PcapError exception
    
    device is a string that specifies the network device to open; 
        on Linux systems with 2.2 or later kernels, a device argument of "any" or NULL 
        can be used to capture packets from all interfaces. 
    
    snaplen specifies the maximum number of bytes to capture. 
        If this value is less than the size of a packet that is captured, 
        only the first snaplen bytes of that packet will be captured and provided as packet data. 
        A value of 65535 should be sufficient, on most if not all networks, to capture all the data available from the packet. 
    
    promisc specifies if the interface is to be put into promiscuous mode. 
        (Note that even if this parameter is false, the interface could well be in promiscuous mode for some other reason.) 
        For now, this doesn't work on the "any" device; if an argument of "any" or NULL is supplied, the promisc flag is ignored
    
    to_ms specifies the read timeout in milliseconds. 
        The read timeout is used to arrange that the read not necessarily return immediately when a packet is seen, 
        but that it wait for some amount of time to allow more packets to arrive and to read multiple packets from the OS kernel in one operation. 
        Not all platforms support a read timeout; on platforms that don't, the read timeout is ignored. 
        A zero value for to_ms, on platforms that support a read timeout, 
        will cause a read to wait forever to allow enough packets to arrive, with no timeout. 
    
    ignore_warn 
        whether raise a PcapWarning exception if pcap_open_live() succeeds with warning 
    '''
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    _pcap.pcap_open_live.restype = pcap_t_p
    hpcap = _pcap.pcap_open_live(device.encode(), snaplen, int(promisc), to_ms, errbuf)
    if hpcap:
        warning = errbuf.raw.decode()
        if warning[0] != '\x00' and not ignore_warn:
            raise  PcapWarning(errbuf.raw.decode())
        return hpcap
    else:
        raise PcapError(errbuf.raw.decode(errors='replace'))


def pcap_open_offline(filename):			
    '''Open a savefile in the tcpdump/libpcap format to read packets.
    
    if pcap_open_offline() fails, raise a PcapError exception

    pcap_open_offline() is called to open a "savefile" for reading. 
    filename specifies the name of the file to open. 
    The file has the same format as those used by tcpdump(1) and tcpslice(1). 
    The name "-" in a synonym for stdin. Alternatively,
    '''
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    _pcap.pcap_open_offline.restype = pcap_t_p
    hpcap = _pcap.pcap_open_offline(filename.encode(), errbuf)
    if hpcap:
        return hpcap
    else:
        raise PcapError(errbuf.raw.decode())
    
def pcap_open_dead(linktype, snaplen):            
    '''Create a pcap_t structure without starting a capture.

    pcap_open_dead() is used for creating a pcap_t structure to use when calling the other functions in libpcap. 
    It is typically used when just using libpcap for compiling BPF code.   
    '''
    _pcap.pcap_open_dead.restype = pcap_t_p
    hpcap = _pcap.pcap_open_dead(linktype, snaplen)
    return hpcap

def pcap_dump_open(hpcap, fname):            
    '''Open a file to write packets.

    pcap_dump_open() is called to open a "savefile" for writing. 
    The name "-" in a synonym for stdout. NULL is returned on failure. 
    hpcap is a pcap struct as returned by pcap_open_offline() or pcap_open_live(). 
    fname specifies the name of the file to open. 
    
    if pcap_dump_open() fails, raise a PcapError exception
    '''
    _pcap.pcap_dump_open.restype = pcap_dumper_t_p
    pdumper = _pcap.pcap_dump_open(hpcap, fname.encode())
    if pdumper:
        return pdumper
    else:
        raise PcapError(pcap_geterr(hpcap)) 
    

def pcap_dump( pdumper, pkthdr_p, data):
    '''Save a packet to disk.
    
    pcap_dump() outputs a packet to the "savefile" opened with pcap_dump_open(). Note that its calling arguments are suitable for use with pcap_dispatch() or pcap_loop(). If called directly, the user parameter is of type pcap_dumper_t as returned by pcap_dump_open().  
    '''
    _pcap.pcap_dump(pdumper, pkthdr_p, data)
    

def pcap_dump_ftell(pdumper):
    '''Return the file position for a "savefile".
    
    pcap_dump_ftell() returns the current file position for the "savefile", 
    representing the number of bytes written by pcap_dump_open() and pcap_dump() . 
    raise a PcapError exception on error.
    '''
    _pcap.pcap_dump_ftell.restype = c_long
    retdata = _pcap.pcap_dump_ftell(pdumper)
    if retdata == -1:
        raise PcapError('call pcap_dump_ftell failed') 
    
    return retdata

def pcap_dump_flush(pdumper):
    '''
    Flushes the output buffer to the ``savefile,'' 
    so that any packets written with pcap_dump() but not yet written to the ``savefile'' will be written. 
    raise a PcapError exception on error.
    '''
    retcode = _pcap.pcap_dump_flush(pdumper)
    if retcode == -1:
        raise PcapError('call pcap_dump_flush failed') 

def pcap_dump_close(pdumper):
    '''Closes a savefile.
    '''
    _pcap.pcap_dump_close(pdumper)


def pcap_findalldevs():       
    '''Construct a list of network devices that can be opened with pcap_open_live().
    
    Note:
    that there may be network devices that cannot be opened with pcap_open_live() by the process calling pcap_findalldevs(), 
    because, for example, that process might not have sufficient privileges to open them for capturing;
    if so, those devices will not appear on the list. 
    alldevsp is set to point to the first element of the list; each element of the list is of type pcap_if_t,
    
    raise a PcapError exception on failure.
    '''
    alldevsp = pcap_if_t_p()
    alldevsp_p = POINTER(pcap_if_t_p)(alldevsp) 
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    retcode = _pcap.pcap_findalldevs(alldevsp_p, errbuf)
    if retcode == -1:
        raise PcapError(errbuf) 
    return alldevsp


def pcap_freealldevs(alldevsp):
    '''Free an interface list returned by pcap_findalldevs().
    
    pcap_freealldevs() is used to free a list allocated by pcap_findalldevs().
    '''    
    _pcap.pcap_freealldevs(alldevsp)
    
def pcap_next(hpcap):
    '''Return the next available pcap_pkthdr and packet.

    pcap_next() reads the next packet (by calling pcap_dispatch() with a cnt of 1) and returns a touple(pcap_pkthdr, packet) .
    (None, None) is returned if an error occured,  or if no packets were read from a live capture 
    (if, for example, they were discarded because they didn't pass the packet filter, or if, 
    on platforms that support a read timeout that starts before any packets arrive, 
    the timeout expires before any packets arrive, 
    or if the file descriptor for the capture device is in non-blocking mode and no packets were available to be read), 
    or if no more packets are available in a ``savefile.'' Unfortunately, 
    there is no way to determine whether an error occured or not.
    '''
    _pcap.pcap_next.restype = c_ubyte_p
    pkthdr = pcap_pkthdr() 
    data = _pcap.pcap_next(hpcap, pointer(pkthdr)) 
    if data:
        return (pkthdr, string_at(data, pkthdr.caplen))
    else:
        return (None, None)

def pcap_next_ex(hpcap):
    '''Read a packet from an interface or from an offline capture.
    
    return (None, None) if no packets were read from a live capture or  if the timeout set with pcap_open_live() has elapsed
    raise PcapError if an error occured
    '''
    pkthdr_p = pcap_pkthdr_p()
    data = c_ubyte_p()
    retcode = _pcap.pcap_next_ex(hpcap, pointer(pkthdr_p), pointer(data)) 
    if retcode == 1: #1 if the packet has been read without problems
        return (pkthdr_p.contents, string_at(data, pkthdr_p.contents.caplen))
    elif retcode == 0 or retcode == -2:
        #0 if the timeout set with pcap_open_live() has elapsed. 
        #-2 if EOF was reached reading from an offline capture
        return (None, None)
    else: #-1 if an error occurred
        raise PcapError(pcap_geterr(hpcap)) 

pcap_handler = CFUNCTYPE(None, POINTER(py_object), pcap_pkthdr_p, c_ubyte_p)

def __callback_wrapper(user_data, pkthdr_p, data):
    (callback, obj) = user_data.contents.value
    if callback:
        callback(pkthdr_p.contents, string_at(data, pkthdr_p.contents.caplen), obj) 

def pcap_dispatch(hpcap, cnt, callback, user_data):
    '''Collect a group of packets.

    pcap_dispatch() is used to collect and process packets. 
    raise PcapError if an error occured.

    cnt specifies the maximum number of packets to process before returning.
        This is not a minimum number; when reading a live capture, 
        only one bufferful of packets is read at a time, so fewer than cnt packets may be processed.
        A cnt of -1 processes all the packets received in one buffer when reading a live capture, 
        or all the packets in the file when reading a ``savefile''. 

    callback specifies a routine to be called with three arguments: 
        1. a pcap_pkthdr,
        2.first caplen (as given in the pcap_pkthdr which is passed to the callback routine) bytes of data from the packet 
        3. a object which is passed in from pcap_dispatch(), 
    
    The number of packets read is returned. 
        0 is returned if no packets were read from a live capture 
        (if, for example, they were discarded because they didn't pass the packet filter, 
        or if, on platforms that support a read timeout that starts before any packets arrive, 
        the timeout expires before any packets arrive, 
        or if the file descriptor for the capture device is in non-blocking mode and no packets were available to be read) 
        or if no more packets are available in a ``savefile.'' 
        
        A return of -2 indicates that the loop terminated due to a call to pcap_breakloop() before any packets were processed. 
        If your application uses pcap_breakloop(), make sure that you explicitly check for -1 and -2, 
        rather than just checking for a return value < 0.

    Note:
        when reading a live capture, pcap_dispatch() will not necessarily return when the read times out; 
        on some platforms, the read timeout isn't supported, and, on other platforms, 
        the timer doesn't start until at least one packet arrives. 
        This means that the read timeout should NOT be used in, for example, an interactive application, 
        to allow the packet capture loop to ``poll'' for user input periodically, 
        as there's no guarantee that pcap_dispatch() will return after the timeout expires.
    '''
    retcode = _pcap.pcap_dispatch(hpcap, cnt, pcap_handler(__callback_wrapper),pointer(py_object((callback, user_data))))
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap)) 
    return retcode

def pcap_loop (hpcap, cnt, callback, user_data):
    '''Collect a group of packets.

    pcap_loop() is similar to pcap_dispatch() except it keeps reading packets until cnt packets are processed or an error occurs.
    It does not return when live read timeouts occur. 
    Rather, specifying a non-zero read timeout to pcap_open_live() and then calling pcap_dispatch() allows the reception 
    and processing of any packets that arrive when the timeout occurs. 
    
    A negative cnt causes pcap_loop() to loop forever (or at least until an error occurs). 
    
    raise PcapError on an error; 
    0 is returned if cnt is exhausted; 
    -2 is returned if the loop terminated due to a call to pcap_breakloop() before any packets were processed. 

    Note:
        In  older  versions  of libpcap, the behavior when cnt was 0 was undefined; 
        different platforms and devices  behaved  differently,  so  code
        that  must work with older versions of libpcap should use -1, not 0, as
        the value of cnt.
    '''
    retcode = _pcap.pcap_loop(hpcap, cnt, pcap_handler(__callback_wrapper),pointer(py_object((callback, user_data))))
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap)) 
    return retcode

def pcap_close(hpcap):
    '''close the files associated with p and deallocates resources.
    '''
    _pcap.pcap_close(hpcap) 

def pcap_breakloop(hpcap):
    '''set a flag that will force pcap_dispatch() or pcap_loop() to return rather than looping.

    They will return the number of packets that have been processed so far, or -2 if no packets have been processed so far. 
    This routine is safe to use inside a signal handler on UNIX or a console control handler on Windows, 
    as it merely sets a flag that is checked within the loop. 
    The flag is checked in loops reading packets from the OS - a signal by itself will not necessarily terminate those loops - 
    as well as in loops processing a set of packets returned by the OS. 
    Note that if you are catching signals on UNIX systems that support restarting system calls after a signal, 
    and calling pcap_breakloop() in the signal handler, you must specify, when catching those signals, 
    that system calls should NOT be restarted by that signal. 
    Otherwise, if the signal interrupted a call reading packets in a live capture, 
    when your signal handler returns after calling pcap_breakloop(), the call will be restarted, 
    and the loop will not terminate until more packets arrive and the call completes.

    Note:
        pcap_next() will, on some platforms, loop reading packets from the OS; 
        that loop will not necessarily be terminated by a signal, 
        so pcap_breakloop() should be used to terminate packet processing even if pcap_next() is being used. 
        pcap_breakloop() does not guarantee that no further packets will be processed by pcap_dispatch() 
        or pcap_loop() after it is called; at most one more packet might be processed. 
        If -2 is returned from pcap_dispatch() or pcap_loop(), 
        the flag is cleared, so a subsequent call will resume reading packets. 
        If a positive number is returned, the flag is not cleared, so a subsequent call will return -2 and clear the flag.
    '''
    _pcap.pcap_breakloop(hpcap)

def pcap_compile(hpcap, buf, optimize, netmask):
    '''Compile a packet filter, converting an high level filtering expression in a program 
        that can be interpreted by the kernel-level filtering engine.

    pcap_compile() is used to compile the string buf into a filter program. 
    
    optimize controls whether optimization on the resulting code is performed. 
    netmask specifies the IPv4 netmask of the network on which packets are being captured; 
        it is used only when checking for IPv4 broadcast addresses in the filter program. 
        If the netmask of the network on which packets are being captured isn't known to the program, 
        or if packets are being captured on the Linux "any" pseudo-interface that can capture on more than one network, 
        a value of 0 can be supplied; 
    
    tests for IPv4 broadcast addreses won't be done correctly, but all other tests in the filter program will be OK. 
    
    return a pointer to a bpf_program struct
    raise PcapError on an error. 
    '''
    bpf_p = bpf_program_p(bpf_program())
    retcode = _pcap.pcap_compile(hpcap, bpf_p, buf.encode(), int(optimize), c_uint32(netmask))
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap)) 
    return bpf_p


def pcap_compile_nopcap(snaplen, linktype, buf, optimize, netmask):
    '''Compile a packet filter without the need of opening an adapter. 
    This function converts an high level filtering expression in a program 
    that can be interpreted by the kernel-level filtering engine.
    
    pcap_compile_nopcap() is similar to pcap_compile() except that instead of passing a pcap structure, 
    one passes the snaplen and linktype explicitly.
    It is intended to be used for compiling filters for direct BPF usage, 
    without necessarily having called pcap_open(). 
    
    pcap_compile_nopcap() return a pointer to a bpf_program struct
    raise PcapError on an error, but the error text is unavailable. 
    
    pcap_compile_nopcap() is a wrapper around pcap_open_dead(), pcap_compile(), and pcap_close(); 
    the latter three routines can be used directly in order to get the error text for a compilation error.
    '''
    bpf_p = bpf_program_p(bpf_program())
    retcode = _pcap.pcap_compile_nopcap(snaplen, linktype, bpf_p, buf.encode(), int(optimize), c_uint32(netmask))
    if retcode == -1:
        raise PcapError('call pcap_compile_nopcap failed') 
    return bpf_p

def pcap_freecode(fp):
    '''Free a filter.

    pcap_freecode() is used to free up allocated memory pointed to by a bpf_program struct generated by pcap_compile() 
    when that BPF program is no longer needed, 
    for example after it has been made the filter program for a pcap structure by a call to pcap_setfilter().
    '''
    _pcap.pcap_freecode(fp)
    
def pcap_setfilter(hpcap, fp):
    '''Associate a filter to a capture.

    pcap_setfilter() is used to specify a filter program. 
    fp is a pointer to a bpf_program struct, usually the result of a call to pcap_compile(). 
    
    raise PcapError on failure. 
    '''
    retcode = _pcap.pcap_setfilter(hpcap, fp)
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap)) 
    
def pcap_getnonblock(hpcap):
    '''Get the "non-blocking" state of an interface.

    pcap_getnonblock() returns the current "non-blocking" state of the capture descriptor; 
    it always returns False on "savefiles". 
    If there is an error, raise PcapError exception.
    '''
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    retcode = _pcap.pcap_getnonblock(hpcap, errbuf)
    if retcode == 0:
        return False
    elif retcode == -1:
        raise PcapError(errbuf.raw.decode())
    else:
        return True

def pcap_setnonblock(hpcap, nonblock):
    '''Switch between blocking and nonblocking mode.

    pcap_setnonblock() puts a capture descriptor, opened with pcap_open_live(), into "non-blocking" mode, 
    or takes it out of "non-blocking" mode, depending on whether the nonblock argument is True or False. 
    It has no effect on "savefiles". 
    If there is an error, raise PcapError exception 
    In "non-blocking" mode, an attempt to read from the capture descriptor with pcap_dispatch() will, 
    if no packets are currently available to be read, 
    return 0 immediately rather than blocking waiting for packets to arrive. 
    pcap_loop() and pcap_next() will not work in "non-blocking" mode.
    '''
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    retcode = _pcap.pcap_setnonblock(hpcap, int(nonblock), errbuf)
    if retcode == -1:
        raise PcapError(errbuf.raw.decode())

def pcap_snapshot(hpcap):
    '''Return the dimension of the packet portion (in bytes) that is delivered to the application.
    
    pcap_snapshot() returns the snapshot length specified when pcap_open_live was called.
    
    '''
    return _pcap.pcap_snapshot(hpcap)



def pcap_is_swapped(hpcap):
    '''returns true if the current savefile uses a different byte order than the current system.
    '''
    return bool(_pcap.pcap_is_swapped(hpcap))


def pcap_major_version(hpcap):
    '''return the major version number of the pcap library used to write the savefile.
    '''
    return _pcap.pcap_major_version(hpcap)


def pcap_minor_version(hpcap):
    '''return the minor version number of the pcap library used to write the savefile.
    '''
    return _pcap.pcap_minor_version(hpcap)


def pcap_lib_version():
    '''Returns a pointer to a string giving information about the version of the libpcap library being used; 
    note that it contains more information than just a version number.
    '''
    _pcap.pcap_lib_version.restype = c_char_p
    version = _pcap.pcap_lib_version()
    return version.decode()

def pcap_stats(hpcap):
    '''Return statistics on current capture.

    pcap_stats() returns a pcap_stat struct. 
    The values represent packet statistics from the start of the run to the time of the call.
    pcap_stats() is supported only on live captures, not on "savefiles"; 
    no statistics are stored in "savefiles", so no statistics are available when reading from a "savefile".
    
    If there is an error, raise PcapError exception.
    '''
    
    pstat = pcap_stat()
    retcode = _pcap.pcap_stats(hpcap, pointer(pstat))
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap)) 
    
    return pstat


def pcap_datalink_name_to_val(name):
    '''Translates a data link type name, 
    which is a DLT_ name with the DLT_ removed, 
    to the corresponding data link type value. 
    The translation is case-insensitive. 
    
    raise PcapError exception on failure
    '''
    retcode = _pcap.pcap_datalink_name_to_val(name.encode())
    if retcode == -1:
        raise PcapError('call pcap_datalink_name_to_val failed') 
    return retcode

def pcap_datalink_val_to_description(dlt):
    '''Translates a data link type value to a short description of that data link type. 
    raise PcapError exception on failure.
    '''
    _pcap.pcap_datalink_val_to_description.restype = c_char_p
    data = _pcap.pcap_datalink_val_to_description(dlt)
    if not data:
        raise PcapError('call pcap_datalink_val_to_description failed') 
    return data.decode()

def pcap_datalink_val_to_name(dlt):
    '''Translates a data link type value to the corresponding data link type name. 
    raise PcapError exception on failure.
    '''
    _pcap.pcap_datalink_val_to_name.restype = c_char_p
    data = _pcap.pcap_datalink_val_to_name(dlt)
    if not data:
        raise PcapError('call pcap_datalink_val_to_name failed') 
    return data.decode()

def pcap_set_datalink(hpcap, dlt):
    '''Set the current data link type of the pcap descriptor to the type specified by dlt.
    raise PcapError exception on failure.
    '''
    retcode = _pcap.pcap_set_datalink(hpcap, dlt)
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap)) 
    
def pcap_datalink(hpcap):
    '''Return the link layer of an adapter.
    '''
    return _pcap.pcap_datalink(hpcap)


def pcap_list_datalinks(hpcap):
    '''list datalinks

    pcap_list_datalinks() is used to get a list of the supported data link types of the interface 
    associated with the pcap descriptor. 
    '''
    dlt_buf = c_int_p()
    retcode = _pcap.pcap_list_datalinks(hpcap, pointer(dlt_buf))
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap)) 

    dlt_buf_a = cast(dlt_buf, POINTER(c_int * retcode)).contents

    datalinks = [ dlt_buf_a[i] for i in range(0, retcode) ]

    _pcap.pcap_free_datalinks(dlt_buf)  #pcap_free_datalinks not exported before winpcap 4.1.2

    return datalinks
    
def pcap_sendpacket(hpcap, buf):            
    '''Send a raw packet.

    This function allows to send a raw packet to the network. 
    hpcap is the interface that will be used to send the packet, 
    buf contains the data of the packet to send (including the various protocol headers), 
    size is the dimension of the buffer pointed by buf, i.e. the size of the packet to send. 
    The MAC CRC doesn't need to be included, 
    because it is transparently calculated and added by the network interface driver. 

    raise PcapError exception on failure.
    '''
    retcode = _pcap.pcap_sendpacket(hpcap, buf, len(buf))
    if retcode == -1:
        raise PcapError(pcap_geterr(hpcap))
