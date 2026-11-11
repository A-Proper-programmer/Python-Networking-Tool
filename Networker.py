import socket, threading, time, itertools, concurrent.futures, getmac
import scapy.all as scapy
import common_ports, port_scanner


def percentage_bar(a,b):
    global N_PORTS_SCANNED
    total = a*b
    while N_PORTS_SCANNED!=total:
        print(f"\r\033[K{N_PORTS_SCANNED} ports have been scanned out of {total} ports. {(N_PORTS_SCANNED/total)*100}%", end="")
        time.sleep(0.08)
    print(f"\r\033[K{N_PORTS_SCANNED} ports have been scanned out of {total} ports. 100%")

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]
    except Exception: ip = "{IP could not be found}"
    finally: s.close()
    return ip

def find_devices():
    global LOCAL_SUBNET, LOCAL_IP
    arp_request = scapy.ARP(pdst=LOCAL_SUBNET+"0/24")
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    devices = [device[1] for device in scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]]
    device_IPs = [device[1].psrc for device in devices]+ [LOCAL_IP]
    device_MAC = [device[1].hwsrc for device in devices] + [getmac.get_mac_address()]
    return device_IPs,  device_MAC

def get_device_data():
    global DEVICES
    DEVICES = []
    device_ip, device_mac = find_devices()
    for i in range(len(device_ip)):
        try: name, _, _ = socket.gethostbyaddr(device_ip[i])
        except socket.herror: name = "Name Not Found"
        DEVICES += [(device_ip[i], device_mac[i], name)]

def port_scan_threader(hard=False, protocol="TCP"):
    global LOCAL_SUBNET, COMMON_TCP_PORTS, DEVICES_IP, N_PORTS_SCANNED, COMMON_UDP_PORTS
    N_PORTS_SCANNED = 0
    ports = range(65536) if hard else list(COMMON_TCP_PORTS.keys()) 
    if protocol=="UDP": ports = list(COMMON_UDP_PORTS.keys())

    thread = threading.Thread(target=percentage_bar, args=(len(ports),len(DEVICES_IP)))
    thread.start()
    with concurrent.futures.ThreadPoolExecutor(max_workers=800) as executor:
        _ = list(executor.map(port_scan, list(itertools.product(DEVICES_IP, ports)), [protocol]*(len(DEVICES_IP)*len(ports))))
    thread.join()

def port_scan(combination, protocol="TCP"):
    global PORT_SCAN_LOG, N_PORTS_SCANNED
    ip,port = combination
    if protocol=="TCP" and port_scanner.tcp_scan(port, ip):
        PORT_SCAN_LOG[ip].update({port:"Open"})
    elif protocol=="UDP":
        result = port_scanner.udp_scan(port, ip)
        PORT_SCAN_LOG[ip].update({port:result})
    
    N_PORTS_SCANNED+=1


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
    global LOCAL_IP, LOCAL_SUBNET, DEVICES_IP, DEVICES_MAC, DEVICES_NAME, PORT_SCAN_LOG    
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
    get_device_data()
    DEVICES_IP = [i[0] for i in DEVICES]                                        # Eg: [192.168.20.1, 192.168.20.15]

    PORT_SCAN_LOG = dict(zip(DEVICES_IP, [{} for _ in range(len(DEVICES_IP))]))

    if choice==1: print(f"Your local IP address is {LOCAL_IP}")
    elif choice==2: 
        print("|  IP  ADDRESS  |    MAC ADDRESS    |       NAME       |")
        DEVICES_MAC = [i[1] for i in DEVICES]
        DEVICES_NAME = [i[2] for i in DEVICES]
        for i in range(len(DEVICES)):
            print(f'|{DEVICES_IP[i]:<15}|{DEVICES_MAC[i]:<19}|{DEVICES_NAME[i]:<18}|')

    elif choice==3: port_scan_threader(); port_scan_threader(protocol="UDP"); print_port_scan_log()
    elif choice==4: port_scan_threader(hard=True); print_port_scan_log()
    elif choice==0: return "E"
    print(f"\nExecution time: {time.perf_counter()-start_time:.6f} seconds\n", "-"*51, sep="")

while True:
    if main() == "E":
        break