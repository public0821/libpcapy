'''
libpcap.py contains the function in libpcap but not in winpcap, not all function are already implemented
'''

from .pcap import _pcap, PcapError, PCAP_ERRBUF_SIZE, pcap_t_p
from ctypes import *
from libpcapy.pcap import PcapWarning

# Error codes for the pcap API.
# These will all be negative, so you can check for the success or
# failure of a call that returns these codes by checking for a
# negative value.

PCAP_ERROR = -1	# generic error code 
PCAP_ERROR_BREAK = -2	# loop terminated by pcap_breakloop 
PCAP_ERROR_NOT_ACTIVATED = -3	# the capture needs to be activated 
PCAP_ERROR_ACTIVATED = -4	# the operation can't be performed on already activated captures 
PCAP_ERROR_NO_SUCH_DEVICE = -5	# no such device exists 
PCAP_ERROR_RFMON_NOTSUP = -6	# this device doesn't support rfmon (monitor) mode 
PCAP_ERROR_NOT_RFMON = -7	# operation supported only in monitor mode 
PCAP_ERROR_PERM_DENIED = -8	# no permission to open the device 
PCAP_ERROR_IFACE_NOT_UP = -9	# interface isn't up 
PCAP_ERROR_CANTSET_TSTAMP_TYPE = -10	# this device doesn't support setting the time stamp type 
PCAP_ERROR_PROMISC_PERM_DENIED = -11	# you don't have permission to capture in promiscuous mode 

# Warning codes for the pcap API.
# These will all be positive and non-zero, so they won't look like
# errors.
PCAP_WARNING = 1	# generic warning code
PCAP_WARNING_PROMISC_NOTSUP = 2	# this device doesn't support promiscuous mode
PCAP_WARNING_TSTAMP_TYPE_NOTSUP = 3	# the requested time stamp type is not supported


def pcap_create(device):
    '''create a live capture handle

       pcap_create()  is  used  to  create  a packet capture handle to look at
       packets on the network.  source is a string that specifies the  network
       device  to  open;  on Linux systems with 2.2 or later kernels, a source
       argument of "any" or NULL can be  used  to  capture  packets  from  all
       interfaces.

       The returned handle must be activated with pcap_activate() before pack-
       ets can be captured with it; options for the capture, such as promiscu-
       ous mode, can be set on the handle before activating it.
    '''
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    _pcap.pcap_create.restype = pcap_t_p
    hpcap = _pcap.pcap_create(device.encode(), errbuf)
    if hpcap:
        return hpcap
    else:
        raise PcapError(errbuf.raw.decode())

__pcap_errno_str={}
__pcap_errno_str[PCAP_ERROR_BREAK]="loop terminated by pcap_breakloop"
__pcap_errno_str[PCAP_ERROR_NOT_ACTIVATED]="the capture needs to be activated"
__pcap_errno_str[PCAP_ERROR_ACTIVATED]="the operation can't be performed on already activated captures"
__pcap_errno_str[PCAP_ERROR_NO_SUCH_DEVICE]="no such device exists"
__pcap_errno_str[PCAP_ERROR_RFMON_NOTSUP]="this device doesn't support rfmon (monitor) mode"
__pcap_errno_str[PCAP_ERROR_NOT_RFMON]="operation supported only in monitor mode"
__pcap_errno_str[PCAP_ERROR_PERM_DENIED]="no permission to open the device"
__pcap_errno_str[PCAP_ERROR_IFACE_NOT_UP]="interface isn't up"
__pcap_errno_str[PCAP_ERROR_CANTSET_TSTAMP_TYPE]="this device doesn't support setting the time stamp type"
__pcap_errno_str[PCAP_ERROR_PROMISC_PERM_DENIED]="you don't have permission to capture in promiscuous mode"
__pcap_warnno_str={}
__pcap_warnno_str[PCAP_WARNING_PROMISC_NOTSUP]="this device doesn't support promiscuous mode"
__pcap_warnno_str[PCAP_WARNING_TSTAMP_TYPE_NOTSUP]="the requested time stamp type is not supported"



def __pcap_check_retcode(hpcap, retcode):
    if retcode == 0:
        return
    elif retcode == PCAP_ERROR:
        _pcap.pcap_geterr.restype = c_char_p
        err = _pcap.pcap_geterr(hpcap)     
        raise PcapError(err.decode())
    elif retcode == PCAP_WARNING:
        _pcap.pcap_geterr.restype = c_char_p
        err = _pcap.pcap_geterr(hpcap)     
        raise PcapWarning(err.decode())
    elif retcode < 0:
        raise PcapError(__pcap_errno_str[retcode], retcode)
    else:
        raise PcapWarning(__pcap_warnno_str[retcode], retcode)

def pcap_set_snaplen(hpcap, len):
    '''set the snapshot length for a not-yet-activated cap-ture handle
       
       sets the snapshot length to be  used  on  a  capture
       handle when the handle is activated to snaplen
    '''
    retcode = _pcap.pcap_set_snaplen(hpcap, len)
    __pcap_check_retcode(hpcap, retcode)

def pcap_set_promisc(hpcap, is_promisc):
    '''set promiscuous mode for a not-yet-activated capture handle
    
    sets whether promiscuous mode should  be  set  on  a
    capture  handle  when the handle is activated.  If promisc is non-zero,
    promiscuous mode will be set, otherwise it will not be set.
    '''
    retcode = _pcap.pcap_set_promisc(hpcap, int(is_promisc))
    __pcap_check_retcode(hpcap, retcode)

def pcap_can_set_rfmon(hpcap):
    '''check whether monitor mode can be set for a not-yet-activated capture handle
    
    checks whether monitor mode could be set on a capture handle when the handle is activated
    '''
    retcode = _pcap.pcap_can_set_rfmon(hpcap)
    if retcode == 0:
        return False
    elif retcode == 1:
        return True
    else:
        __pcap_check_retcode(hpcap, retcode)

def pcap_set_rfmon(hpcap, is_rfmon):
    '''set monitor mode for a not-yet-activated capture handle

    sets whether monitor mode should be set on  a  capture
    handle  when  the  handle  is activated.  If rfmon is non-zero, monitor
    mode will be set, otherwise it will not be set.
    '''
    retcode = _pcap.pcap_set_rfmon(hpcap, int(is_rfmon))
    __pcap_check_retcode(hpcap, retcode)

def pcap_set_timeout(hpcap, timeout):
    '''set the read timeout for a not-yet-activated capture handle

    sets the read timeout that will be used on a capture
    handle when the handle is activated to to_ms, which is in units of milliseconds.
    '''
    __pcap_check_retcode(hpcap, _pcap.pcap_set_timeout(hpcap, timeout))

#def pcap_set_tstamp_type(hpcap, tstamp_type):
    #'''set the time stamp type to be used by a capture device

    #sets the the type  of  time  stamp  desired  for
    #packets  captured  on  the  pcap  descriptor  to  the type specified by
    #tstamp_type.  It must  be  called  on  a  pcap  descriptor  created  by
    #pcap_create()  that  has  not  yet  been  activated by pcap_activate().
    #pcap_list_tstamp_types() will give a list of the time stamp types  sup-
    #ported by a given capture device.  See pcap-tstamp(7) for a list of all
    #the time stamp types.
    #'''
    #__pcap_check_retcode(hpcap, _pcap.pcap_set_tstamp_type(hpcap, tstamp_type))

def pcap_set_buffer_size(hpcap, size):
    '''set the buffer size for a not-yet-activated capture handle

    sets the buffer size that will be used on a capture  
    handle  when  the handle is activated to buffer_size, which is in
    units of bytes.
    '''
    __pcap_check_retcode(hpcap, _pcap.pcap_set_buffer_size(hpcap, size))

def pcap_active(hpcap):
    '''activate a capture handle

    used to activate a packet capture handle to look at
    packets on the network, with the options that were set  on  the  handle
    being in effect.
    '''
    __pcap_check_retcode(hpcap, _pcap.pcap_active(hpcap))

