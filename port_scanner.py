from scapy.all import *
from scapy.layers.inet import IP, TCP
from ipaddress import ip_address
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Basic port scanner that mimics the behaviour of hping3.")
    parser.add_argument('-i', '--ip', type=ip_address, required=True, help="Target IP address capture on")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port to scan on")
    parser.add_argument('-d', '--delay', type=int, required=False, help="Delay in milliseconds between each scan")

    return parser.parse_args()

def port_scan(target_ip, target_port):
    resp = sr1(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), verbose=False, timeout=1)

    if resp is not None and TCP in resp:
        if resp[TCP].flags == 18:  
            return True  
    return False  

def main():
    args = parse_args()
    scan = port_scan(args.ip, args.port)
    print(scan)
    if scan:
        print(f"Port {args.port} on {args.ip} is open")
    else:
        print(f"Port {args.port} on {args.ip} is open")

if __name__ == "__main__":
    main()


