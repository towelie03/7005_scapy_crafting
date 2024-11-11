from scapy.all import * # for some reason the wildcard from the notes imoprt from the notes doosent work so I had to import it like this 
from scapy.layers.inet import IP, TCP, ICMP
from ipaddress import ip_address
import argparse
import time
import sys

def parse_args():
    parser = argparse.ArgumentParser(description="Basic port scanner that mimics the behaviour of hping3. If no start and end port is specified then it defaults the scan from port 1-65535")
    parser.add_argument('ip', type=ip_address, help="Target IP address to capture on")
    parser.add_argument('-s', '--start', type=int, default=1, help="Start port number (default is 1)")
    parser.add_argument('-e', '--end', type=int, default=65535, help="End port number (default is 65535)")
    parser.add_argument('-d', '--delay', type=int, default=0, help="Delay in milliseconds between each scan")

    return parser.parse_args()

def port_scan(target_ip, target_port):
    target_ip_str = str(target_ip)
    resp = sr1(IP(dst=target_ip_str)/TCP(dport=target_port, flags="S"), verbose=False, timeout=1)

    if resp is None:
        return "filtered"

    if TCP in resp:
        if resp[TCP].flags == 18:  # SYN-ACK
            return "open"
        elif resp[TCP].flags == 20:  # RST
            return "closed"
        else:
            return "filtered"

def main():
    args = parse_args()

    ports_to_scan = range(args.start, args.end + 1)
    try:
        for port in ports_to_scan:
            if args.delay > 0:
                time.sleep(args.delay / 1000.0)  # Convert milliseconds to seconds

            scan = port_scan(args.ip, port)

            if scan == "open":
                print(f"Port {port} on {args.ip} is open")
            elif scan == "closed":
                print(f"Port {port} on {args.ip} is closed")
            elif scan == "filtered":
                print(f"Port {port} on {args.ip} is filtered")
    except KeyboardInterrupt:
        print("\n Scan stopped. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()

