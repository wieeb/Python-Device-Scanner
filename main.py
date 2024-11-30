import argparse
import threading
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from scapy.all import sr1, srp, getmacbyip
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
max_threads = 15 
semaphore = threading.Semaphore(max_threads)

# Función para convertir el rango de IPs a una lista
def ip_range_to_list(ip_range):
    ip_parts = ip_range.split("-")
    start_ip = ip_parts[0]
    end_ip = int(ip_parts[1])
    base_ip = ".".join(start_ip.split(".")[:-1])  # Obtener la parte de red
    return [f"{base_ip}.{i}" for i in range(1, end_ip + 1)]

# Función para escanear ICMP
def scan_ICMP(target_IP):
    with semaphore:
        pkt = scapy.IP(dst=target_IP) / scapy.ICMP()
        response = sr1(pkt, timeout=2, verbose=False)
        if response:
            target_MAC = getmacbyip(target_IP)  # ARP QUERY
            print(f"Device found: {response[scapy.IP].src} // MAC: {target_MAC} \n")
        else:
            return 1

# Función para escanear ARP
def scan_ARP(target_IP):
    with semaphore:
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast device
        pkt = broadcast / ARP(op=1, pdst=target_IP)
        response = srp(pkt, timeout=2, verbose=False)[0]
        for x in response:
            print(f"Device found: {x[1].psrc} // MAC: {x[1].hwsrc}")
        return None

# Función para escanear la red
def scan_network(target_list, scan_type="ICMP"):
    status = False
    threads = []
    for target in target_list:
        if scan_type == "ICMP" and status == False:
            print("Starting ICMP scan...")
            status = True
        elif scan_type == "ICMP" and status == True:
            thread = threading.Thread(target=scan_ICMP, args=(target,))
            thread.start()
            threads.append(thread)
        elif scan_type == "ARP":
            thread = threading.Thread(target=scan_ARP, args=(target,))
            thread.start()
            threads.append(thread)

    # Esperar a que todos los hilos terminen
    for thread in threads:
        thread.join()

# Función para manejar los argumentos
def arguments():
    parser = argparse.ArgumentParser(description="Network scanner for ICMP and ARP")
    parser.add_argument("ip_range", help="Range of IPs (ex. 192.168.1.1-50)")
    parser.add_argument("-s", "--scan", choices=["ICMP", "ARP"], default="ICMP", help="Scan type: ICMP or ARP")
    args = parser.parse_args()
    return args

# Función principal
def main():
    args = arguments()
    ip_list = ip_range_to_list(args.ip_range)
    scan_network(ip_list, args.scan)

if __name__ == "__main__":
    main()
