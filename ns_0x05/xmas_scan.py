import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # This is supress scapy warnings
from scapy.all import *

def xmas_scan(dst_ip, dst_port, dst_timeout):
    xmas_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags="FPU"), timeout=dst_timeout)
    if (str(type(xmas_scan_resp)) == "<class 'NoneType'>"):
        return "Open|Filtered"
    elif (xmas_scan_resp.haslayer(TCP)):
        if (xmas_scan_resp.getlayer(TCP).flags == 0x14):# (RST,ACK)
            return "Closed"
    elif (xmas_scan_resp.haslayer(ICMP)):
        if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            return "Filtered"
    else:
        return "CHECK"

if __name__ == '__main__':
    dst_ip = '10.196.28.168'
    dst_port = [53,80,98]
    dst_timeout = 0.01
    for p in dst_port:
    	print('port :',p,xmas_scan(dst_ip,p,dst_timeout))