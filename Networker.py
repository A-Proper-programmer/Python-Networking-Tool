import socket, threading, time, itertools
import scapy.all as scapy

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

def find_devices():
    global LOCAL_SUBNET

    arp_request = scapy.ARP(pdst=LOCAL_SUBNET+"0/24")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    device_ips = [device[1].psrc for device in scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]]
    
    return device_ips

def port_scan_threader(hard=False):
    global LOCAL_SUBNET, COMMON_PORTS, DEVICES
    ports = range(65536) if hard else COMMON_PORTS
    combis = split_list(list(itertools.product(DEVICES, ports)))
    threads = []
    for l in combis:
        thread = threading.Thread(target=port_scan, args=(l,))
        threads.append(thread)
        thread.start()
    for t in threads:
        t.join()

def port_scan(combi=[]):
    global COMMON_PORTS, LOCAL_SUBNET, PORT_SCAN_LOG
    if not combi: return
    for i in combi:
        ip,port = i
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        try: s.connect((ip, port))
        except Exception: continue
        finally: s.close()
        PORT_SCAN_LOG[ip] += [port]

def print_port_scan_log():
    global PORT_SCAN_LOG
    for key in PORT_SCAN_LOG.keys():
        try:
            name, _, _ = socket.gethostbyaddr(key)
            print(f"{key} [{name}]:")
        except socket.herror:
            print(f"{key} [Name Not Found]:")
        
        if PORT_SCAN_LOG[key]: print(f"Open ports: \n\t{sorted(PORT_SCAN_LOG[key])}\n")
        else: print("There are no open ports.\n")

# -------------- MAIN --------------
COMMON_PORTS = [21, 22, 23, 25, 53, 67, 68, 80, 110, 139, 143, 161, 162, 389, 443, 445, 548, 554, 631, 993, 995, 1433, 1900, 2049, 3306, 3389, 5000, 5353, 5357, 5432, 5900, 8008, 8009, 8080, 8443, 9100, 32400]
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

    if type==1: print(f"Your local IP address is {get_local_ip()}")
    elif type==2: print(DEVICES)
    elif type==3: port_scan_threader(); print_port_scan_log()
    elif type==4: port_scan_threader(hard=True); print_port_scan_log()
    elif type==0: return "E"
    print(f"\nExecution time: {time.perf_counter()-start_time:.6f} seconds\n", "-"*51, sep="")

while True:
    if main() == "E":
        break