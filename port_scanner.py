from scapy.all import * # for some reason the wildcard from the notes imoprt from the notes doosent work so I had to import it like this 
from scapy.layers.inet import IP, TCP, ICMP
from ipaddress import ip_address
import argparse
import time

def parse_args():
    parser = argparse.ArgumentParser(description="Basic port scanner that mimics the behaviour of hping3.")
    parser.add_argument('-i', '--ip', type=ip_address, required=True, help="Target IP address to capture on")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port to scan on")
    parser.add_argument('-d', '--delay', type=int, default=0, help="Delay in milliseconds between each scan")

    return parser.parse_args()

def port_scan(target_ip, target_port):

    target_ip_str = str(target_ip)
    resp = sr1(IP(dst=target_ip_str)/TCP(dport=target_port, flags="S"), verbose=False, timeout=1)

    if resp is None:
        return "filtered"

    if TCP in resp:
        if resp[TCP].flags == 18:
            return "open"
        elif resp[TCP].flags == 4:
            return "closed"

    if ICMP in resp:
        if resp[ICMP].type == 3:
            return "filtered"

    return "unknown"

def main():
    args = parse_args()
    if args.delay > 0:
        time.sleep(args.delay / 1000.0)  # Convert milliseconds to seconds

    scan = port_scan(args.ip, args.port)

    if scan == "open":
        print(f"Port {args.port} on {args.ip} is open")
    elif scan == "closed":
        print(f"Port {args.port} on {args.ip} is closed")
    elif scan == "filtered":
        print(f"Port {args.port} on {args.ip} is filtered")
    else:
        print(f"Port {args.port} on {args.ip} status is unknown")

if __name__ == "__main__":
    main()


