import socket
from scapy.all import IP, UDP, ICMP, sr1

def tcp_scan(port, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    try: s.connect((ip, port))
    except Exception: return False
    finally: s.close()
    return True

def udp_scan(port, ip):
    packet = IP(dst=ip)/UDP(dport=port)
    reply = sr1(packet, timeout=2, verbose=0)
    if reply is None:
        return "Filtered"
    elif reply.haslayer(ICMP):
        if reply[ICMP].type==3 and reply[ICMP].code==3:
            return "Closed"
    elif reply.haslayer(UDP):
        return "Open"

