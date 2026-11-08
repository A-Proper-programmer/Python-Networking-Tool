import socket, threading, time, itertools
import scapy.all as scapy
import common_ports, port_scanner

def split_list(l):
    x = len(l)
    max_n = x // 41
    if max_n >= 256: n=min(max_n, 1024)
    else: n=256

    size,rem = divmod(x,n)
    final = []; start = 0; end = size
    for i in range(n):
        final.append(l[start:end+int(i<rem)])
        start = end+int(i<rem)
        end = start+size
    return final

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]
    except Exception: ip = "{IP could not be found}"
    finally: s.close()
    return ip

def percentage_bar(a,b):
    global N_PORTS_SCANNED
    total = a*b
    while N_PORTS_SCANNED!=total:
        print(f"\r\033[K{N_PORTS_SCANNED} ports have been scanned out of {total} ports. {(N_PORTS_SCANNED/total)*100}%", end="")
        time.sleep(0.05)
    print(f"\r\033[K{N_PORTS_SCANNED} ports have been scanned out of {total} ports. 100%")

def find_devices():
    global LOCAL_SUBNET

    arp_request = scapy.ARP(pdst=LOCAL_SUBNET+"0/24")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    device_ips = [device[1].psrc for device in scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]]
    
    return device_ips

def port_scan_threader(hard=False, type="TCP"):
    global LOCAL_SUBNET, COMMON_TCP_PORTS, DEVICES, N_PORTS_SCANNED, COMMON_UDP_PORTS
    N_PORTS_SCANNED = 0
    ports = range(65536) if hard else list(COMMON_TCP_PORTS.keys()) 
    if type=="UDP": ports = list(COMMON_UDP_PORTS.keys())
    combis = split_list(list(itertools.product(DEVICES, ports)))
    threads = []
    for l in combis:
        thread = threading.Thread(target=port_scan, args=(l,type))
        threads.append(thread)
        thread.start()
    thread = threading.Thread(target=percentage_bar, args=(len(ports),len(DEVICES)))
    threads.append(thread)
    thread.start()
    for t in threads:
        t.join()

def port_scan(combi=[], type="TCP"):
    global PORT_SCAN_LOG, N_PORTS_SCANNED
    for i in combi:
        ip,port = i
        N_PORTS_SCANNED+=1
        if type=="TCP" and port_scanner.tcp_scan(port, ip):
            PORT_SCAN_LOG[ip] += [port]
        elif type=="UDP" and port_scanner.udp_scan(port, ip):
            PORT_SCAN_LOG[ip] += [port]


def print_port_scan_log():
    global PORT_SCAN_LOG
    for key in PORT_SCAN_LOG.keys():
        try:
            name, _, _ = socket.gethostbyaddr(key)
            print(f"{key} [{name}]:")
        except socket.herror:
            print(f"{key} [Name Not Found]:")
        
        if PORT_SCAN_LOG[key]:
            print(f"|  PORT  |        SERVICE        |")
            for i in sorted(PORT_SCAN_LOG[key]):
                print(f'|{i:<4}\t |{list(COMMON_TCP_PORTS.get(i, {"Unknown":""}).keys())[0]:<17}\t |')
            print()
        else: print("There are no open ports.\n")

# --------- COMMON PORTS -----------
COMMON_TCP_PORTS = common_ports.COMMON_TCP_PORTS
COMMON_UDP_PORTS = common_ports.COMMON_UDP_PORTS

# -------------- MAIN --------------
print("-------------------- NETWORKER --------------------")

def main():
    global LOCAL_IP, LOCAL_SUBNET, DEVICES, PORT_SCAN_LOG
    LOCAL_IP = get_local_ip()
    if LOCAL_IP[0]=="{": raise SystemExit("Exiting: Local IP fell back to loopback.")
    LOCAL_SUBNET = str(".".join(LOCAL_IP.split(".")[:3]) + ".")
    DEVICES = find_devices()
    PORT_SCAN_LOG = dict(zip(DEVICES, [[] for _ in range(len(DEVICES))]))

    print()
    print("[1] Find your local IP address on your network")
    print("[2] Scan for devices on your network")
    print("[3] Scan common open ports on your network")
    print("[4] Scan for every port on your network (VERY SLOW)")
    print("[0] Exit")

    while True:
        type = input("Enter a function : ")
        try: type = int(type)
        except ValueError: print("Type the mode. Eg: 1, 2, etc")
        else:
            if type not in [0,1,2,3,4]: print("Type an existing mode [0,1,2,3,4].")
            else: break 
    print()
    start_time = time.perf_counter()
    
    if type==1: print(f"Your local IP address is {LOCAL_IP}")
    elif type==2: print(DEVICES)
    elif type==3: port_scan_threader(); print_port_scan_log()
    elif type==4: port_scan_threader(hard=True); print_port_scan_log()
    elif type==0: return "E"
    print(f"\nExecution time: {time.perf_counter()-start_time:.6f} seconds\n", "-"*51, sep="")

while True:
    if main() == "E":
        break