"""
 Author: Ofri Guz
 Date: February 28, 2024,
 Purpose: Targil 6.19
"""
# import modules
from scapy.all import *
from scapy.layers.inet import TCP
from scapy.layers.inet import IP

# Constants
TIMEOUT = 0.5  # in seconds


def check_port(host, port):
    """
    Checks if a specific port is open or closed on a given host.
    prints '.' if port is open and '-' if port is closed
    :param host: The IP address of the target host
    :param port: The port number to check
    """
    try:
        # Construct the SYN packet
        syn_packet = IP(dst=host) / TCP(dport=port, flags="S")
        # Send the SYN packet and wait for a response
        response = sr1(syn_packet, timeout=TIMEOUT, verbose=False)

        # Check the response
        if response and response.haslayer(TCP) and response[TCP].flags == 18:
            print(".", end="", flush=True)  # Print a dot if port is open
        else:
            print("-", end="", flush=True)  # Print a dash if port is closed
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")


def scan_ports(host):
    """
    Scans ports 20-1025 on a target host to see which ports are open/closed
    :param host: The IP address of the target host.
    """
    print(f"Scanning ports on {host}")
    for port in range(20, 1025):
        check_port(host, port)


if __name__ == "__main__":
    target_host = input("Enter the IP address of the target computer: ")
    scan_ports(target_host)
