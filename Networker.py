import socket, threading, time, itertools, concurrent.futures
import scapy.all as scapy
import common_ports, port_scanner

def split_list(l):
    item_count = len(l)
    max_chunk_count = item_count // 41
    if max_chunk_count >= 256: chunk_count=min(max_chunk_count, 1024)
    else: chunk_count=256

    size,rem = divmod(item_count,chunk_count)
    chunks = []; start = 0; end = size
    for i in range(chunk_count):
        chunks.append(l[start:end+int(i<rem)])
        start = end+int(i<rem)
        end = start+size
    return chunks

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
        time.sleep(0.08)
    print(f"\r\033[K{N_PORTS_SCANNED} ports have been scanned out of {total} ports. 100%")

def find_devices():
    global LOCAL_SUBNET
    arp_request = scapy.ARP(pdst=LOCAL_SUBNET+"0/24")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    device_ips = [device[1].psrc for device in scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]]

    return device_ips

def port_scan_threader(hard=False, protocol="TCP"):
    global LOCAL_SUBNET, COMMON_TCP_PORTS, DEVICES, N_PORTS_SCANNED, COMMON_UDP_PORTS
    
    N_PORTS_SCANNED = 0
    ports = range(65536) if hard else list(COMMON_TCP_PORTS.keys()) 
    if protocol=="UDP": ports = list(COMMON_UDP_PORTS.keys())

    combinations = list(itertools.product(DEVICES, ports))
    '''threads = []
    for items in combinations:
        thread = threading.Thread(target=port_scan, args=(items,protocol))
        threads.append(thread); thread.start()'''
    thread = threading.Thread(target=percentage_bar, args=(len(ports),len(DEVICES)))
    thread.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1024) as executor:
        results = list(executor.map(port_scan, combinations, [protocol]*len(combinations)))
    thread.join()


def port_scan(combination, protocol="TCP"):
    global PORT_SCAN_LOG, N_PORTS_SCANNED
    """for i in combi:"""
    ip,port = combination
    N_PORTS_SCANNED+=1
    if protocol=="TCP" and port_scanner.tcp_scan(port, ip):
        PORT_SCAN_LOG[ip].update({port:"Open"})
    elif protocol=="UDP":
        result = port_scanner.udp_scan(port, ip)
        PORT_SCAN_LOG[ip].update({port:result})


def print_port_scan_log():
    global PORT_SCAN_LOG

    for key in PORT_SCAN_LOG.keys():
        try:
            name, _, _ = socket.gethostbyaddr(key)
            print(f"{key} [{name}]:")
        except socket.herror:
            print(f"{key} [Name Not Found]:")

        if PORT_SCAN_LOG[key]:
            print(f"|  PORT  |         SERVICE         |   STATE   |")
            for port in sorted(list(PORT_SCAN_LOG[key].keys())):
                print(f'|{port:<8}|', end="")

                if port in COMMON_TCP_PORTS.keys():
                    print(f'{list(COMMON_TCP_PORTS.get(port, {"Unknown":""}).keys())[0]:<25}|', end="")
                elif port in COMMON_UDP_PORTS.keys():
                    print(f'{list(COMMON_UDP_PORTS.get(port, {"Unknown":""}).keys())[0]:<25}|', end="")
                else: print(f'{"Unknown":<25}|')

                print(f'{PORT_SCAN_LOG[key][port]:<11}|')
            print()
        else: print("There are no open ports.\n")

# --------- COMMON PORTS -----------
COMMON_TCP_PORTS = common_ports.COMMON_TCP_PORTS
COMMON_UDP_PORTS = common_ports.COMMON_UDP_PORTS

# -------------- MAIN --------------
print("-------------------- NETWORKER --------------------")

def main():
    global LOCAL_IP, LOCAL_SUBNET, DEVICES, PORT_SCAN_LOG    
    print()
    print("[1] Find your local IP address on your network")
    print("[2] Scan for devices on your network")
    print("[3] Scan common open ports on your network")
    print("[4] Scan for every port on your network (VERY SLOW)")
    print("[0] Exit")

    while True:
        choice = input("Enter a function : ")
        try: choice = int(choice)
        except ValueError: print("Type the mode. Eg: 1, 2, etc")
        else:
            if choice not in [0,1,2,3,4]: print("Type an existing mode [0,1,2,3,4].")
            else: break 
    print()

    start_time = time.perf_counter()

    LOCAL_IP = get_local_ip()                                                   # Eg: "192.168.20.15"
    if LOCAL_IP=="{IP could not be found}": raise SystemExit("Exiting: Local IP fell back to loopback.")
    LOCAL_SUBNET = str(".".join(LOCAL_IP.split(".")[:3]) + ".")                 # Eg: "192.168.20."
    DEVICES = find_devices()                                                    # Eg: [192.168.20.1, 192.168.20.15]
    PORT_SCAN_LOG = dict(zip(DEVICES, [{} for _ in range(len(DEVICES))]))
    
    if choice==1: print(f"Your local IP address is {LOCAL_IP}")
    elif choice==2: print(f'The devices on your network are {DEVICES}')
    elif choice==3: port_scan_threader(); port_scan_threader(protocol="UDP"); print_port_scan_log()
    elif choice==4: port_scan_threader(hard=True); print_port_scan_log()
    elif choice==0: return "E"
    print(f"\nExecution time: {time.perf_counter()-start_time:.6f} seconds\n", "-"*51, sep="")

while True:
    if main() == "E":
        break