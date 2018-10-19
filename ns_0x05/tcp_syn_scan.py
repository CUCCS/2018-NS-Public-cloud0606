import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # This is supress scapy warnings
from scapy.all import *
def tcp_syn_scan(dst_ip, dst_port, dst_timeout):
    '参考stealth_scan'
    filtered_cnt = 0
    closed_cnt = 0
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=dst_timeout)
    if (str(type(stealth_scan_resp)) == "<class 'NoneType'>"): #
        return "Filtered"
    elif (stealth_scan_resp.haslayer(TCP)):
        if (stealth_scan_resp.getlayer(TCP).flags == 0x12):# (SYN,ACK)
            # 只回复RST，与connect scan的区别
            send_rst = sr(IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R"), timeout=dst_timeout)
            return "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):# (RST,ACK)
            return "Closed"
    elif (stealth_scan_resp.haslayer(ICMP)):
        if (int(stealth_scan_resp.getlayer(ICMP).type) == 3 and
                int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            return "Filtered"
    else:
        return "CHECK"

if __name__ == '__main__':
    dst_ip = '10.196.28.168'
    dst_port = [53,80,98]
    dst_timeout = 0.01
    for p in dst_port:
        print('port :',p,tcp_syn_scan(dst_ip,p,dst_timeout))