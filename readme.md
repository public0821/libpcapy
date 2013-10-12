<meta http-equiv="content-type" content="text/html; charset=UTF-8">
# libpcapy

libpcapy是一个python语言的pcap封装，利用python的ctypes库开发，目前只实现了winpcap和libpcap库都有的函数，特点如下

- 100%纯python，不需要编译任何其他的东西；
- 支持python2.7和python3.2及以上版本；
- 支持windows、linux和darwin(其他unix平台没有测试)
- 函数接口和C语言保持一致，如果熟悉c语言的pcap开发，可以很方便的使用libpcapy

# 需要帮助

- darwin和windows平台的抓包功能还不能正常使用（其他功能正常）

如果你有解决思路或者解决办法，请麻烦告诉我一声，谢谢

# 安装

待完成

# 例子

## 读pcap文件
```python
    from libpcapy import pcap, ptypes
    
    hpcap = pcap.pcap_open_offline('./test.pcap')
    while True:
        (pkthdr, packet) = pcap.pcap_next(hpcap)
        if pkthdr is None:
            break
        print(pkthdr.caplen, pkthdr.len, packet)
            
    pcap.pcap_close(hpcap)
```

## 写pcap文件
```python
    from libpcapy import pcap, ptypes
    import time
    
    hpcap = pcap.pcap_open_dead(ptypes.LINKTYPE_ETHERNET, 65535)
    pdumper = pcap.pcap_dump_open(hpcap, './test.pcap')
    
    data = b'11111111111111111111111111111111111111111111'
    pkthdr = ptypes.pcap_pkthdr()
    pkthdr.caplen = len(data)
    pkthdr.len = len(data)
    now = time.time()
    pkthdr.ts.tv_sec = int(now)
    pkthdr.ts.tv_usec = int(now * 1000 * 1000)%(1000*1000)
    pcap.pcap_dump(pdumper, pointer(pkthdr), data)
    
    pcap.pcap_dump_flush(pdumper)
    pcap.pcap_dump_close(pdumper)
    pcap.pcap_close(hpcap)
```

## 发送数据包
```python
    from libpcapy import pcap, ptypes

    device = 'en0'
    hpcap = pcap.pcap_open_live(device, 65535, True, 0)
    pcap.pcap_sendpacket(hpcap, b'datadatadatatdatadafjasdkfjkasjdfkasdfklajsdfjlksaflsjkfjaskdjfasjfdk') 
    pcap.pcap_close(hpcap) 
```

## 抓包
```python
from libpcapy import pcap, ptypes
import time

device = 'en0'
    
def callback(pkthdr, data, user_data):
    print('%d.%d(%d/%d) '%(pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.caplen, pkthdr.len), data)
    
def capture():
    hpcap = pcap.pcap_open_live(device, 65535, True, 0)
    pcap.pcap_loop(hpcap, -1, callback, None)
    pcap.pcap_close(hpcap)  
```


# 问题

如果有什么建议或者问题，欢迎发送邮件到我的邮箱 public0821@gmail.com
