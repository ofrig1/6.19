from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP


def check_port(host, port):
    try:
        # Construct the SYN packet
        syn_packet = IP(dst=host) / TCP(dport=port, flags="S")
        # Send the SYN packet and wait for a response
        response = sr1(syn_packet, timeout=0.5, verbose=False)

        # Check the response
        if response and response.haslayer(TCP) and response[TCP].flags == 18:
            print(".", end="", flush=True)  # Print a dot if port is open
        else:
            print("-", end="", flush=True)  # Print a dash if port is closed
    except Exception as e:
        pass  # Ignore errors


def scan_ports(host):
    print(f"Scanning ports on {host}")
    for port in range(20, 1025):
        check_port(host, port)


if __name__ == "__main__":
    target_host = input("Enter the IP address of the target computer: ")
    scan_ports(target_host)
