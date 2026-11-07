import socket, threading, time

COMMON_PORTS = [21, 22, 23, 25, 53, 67, 68, 80, 110, 139, 143, 161, 162, 389, 443, 445, 548, 554, 631, 993, 995, 1433, 1900, 2049, 3306, 3389, 5000, 5353, 5357, 5432, 5900, 8008, 8009, 8080, 8443, 9100, 32400]

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]
    except Exception: ip = "127.0.0.1"
    finally: s.close()
    return ip

def port_scan_thread():
    start_time = time.perf_counter()
    local_subnet = ".".join(get_local_ip().split(".")[:3]) + "."
    threads = []
    for t in range(1,65):
        thread = threading.Thread(target=port_scan, args=(local_subnet, t))
        threads.append(thread)
        thread.start()
    for t in threads:
        t.join()
    
    print(f"Execution time: {time.perf_counter()-start_time:.6f} seconds")


def port_scan(local_subnet, thread=0):
    global COMMON_PORTS
    r_1, r_2 = (thread-1)*4, thread*4
    for i in range(r_1, r_2):
        ip = local_subnet+str(i)
        for port in COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            try: s.connect((ip, port))
            except Exception: continue
            finally: s.close()
            print(f"Port {port} is open on {ip}")



print("---------- NETWORKER ----------")
print("[1] Scan ports on your WiFi\n")

while True:
    type = input("Enter a function : ")
    try: type = int(type)
    except ValueError: print("Type the mode. Eg: 1, 2, etc")
    else:
        if type not in [1]: print("Type an existing mode [1].")
        else: break 

if type==1: port_scan_thread()

input("Press Enter to continue...")