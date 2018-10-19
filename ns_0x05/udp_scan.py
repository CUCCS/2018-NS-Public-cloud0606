import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # This is supress scapy warnings
from scapy.all import *

def udp_scan(dst_ip, dst_port, dst_timeout):
    udp_scan_resp = sr1(IP(dst=dst_ip) / UDP(dport=dst_port), timeout=dst_timeout)
    if (str(type(udp_scan_resp)) == "<class 'NoneType'>"):
        retrans = []
        for count in range(0, 3):
            retrans.append(sr1(IP(dst=dst_ip) / UDP(dport=dst_port), timeout=dst_timeout))
        for item in retrans:
            if (str(type(item)) != "<class 'NoneType'>"):
                udp_scan(dst_ip, dst_port, dst_timeout)
        return "Open|Filtered"

    elif (udp_scan_resp.haslayer(UDP) or udp_scan_resp.getlayer(IP).proto == IP_PROTOS.udp):
        return "Open"
    elif (udp_scan_resp.haslayer(ICMP)):
        if (int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) == 3):
            # 3,3 Port Unreachable——端口不可达
            return "Closed"
        elif (int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10,
                                                                                                  13]):
            return "Filtered"
    else:
        return "CHECK"

if __name__ == '__main__':
    dst_ip = '10.0.2.5'
    dst_port = [53,80,98]
    dst_timeout = 1.0
    for p in dst_port:
        print('port :',p,udp_scan(dst_ip,p,dst_timeout))