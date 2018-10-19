import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # This is supress scapy warnings
from scapy.all import *

def tcp_connect_scan(dst_ip, dst_port, dst_timeout):
    '''
    :param dst_ip:string,目标IP
    :param dst_port: 端口号
    :param dst_timeout:
    :return:端口状态
    '''
    src_port = RandShort()
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=dst_timeout)
    if (str(type(tcp_connect_scan_resp)) == "<class 'NoneType'>"):# no responses的情况,端口被过滤
        return("FILTERED")
    elif (tcp_connect_scan_resp.haslayer(TCP)):
        if (tcp_connect_scan_resp.getlayer(TCP).flags == 0x12): # (SYN,ACK)
            send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="AR"), timeout=dst_timeout)# 回复ACK,RST
            return ("OPEN")
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):# (RST,ACK)
            return ("CLOSED")
    else:
        return ("CHECKED")

if __name__ == '__main__':
    dst_ip = '10.0.2.15'
    dst_port = [53,80,98]
    dst_timeout = 5
    for p in dst_port:
        print('port :',p,tcp_connect_scan(dst_ip,p,dst_timeout))
    print('\n')

